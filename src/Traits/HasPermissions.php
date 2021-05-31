<?php

namespace Spatie\Permission\Traits;

use Illuminate\Database\Eloquent\Builder;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsToMany;
use Illuminate\Support\Arr;
use Illuminate\Support\Collection;
use Spatie\Permission\Contracts\Permission;
use Spatie\Permission\Exceptions\GuardDoesNotMatch;
use Spatie\Permission\Exceptions\PermissionDoesNotExist;
use Spatie\Permission\Exceptions\WildcardPermissionInvalidArgument;
use Spatie\Permission\Guard;
use Spatie\Permission\PermissionRegistrar;
use Spatie\Permission\WildcardPermission;

trait HasPermissions
{
    private $permissionClass;

    public static function bootHasPermissions()
    {
        static::deleting(function ($model) {
            if (method_exists($model, 'isForceDeleting') && ! $model->isForceDeleting()) {
                return;
            }

            $model->permissions()->detach();
        });
    }

    public function getPermissionClass()
    {
        if (! isset($this->permissionClass)) {
            $this->permissionClass = app(PermissionRegistrar::class)->getPermissionClass();
        }

        return $this->permissionClass;
    }

    /**
     * A model may have multiple direct permissions.
     */
    public function permissions(): BelongsToMany
    {
        return $this->morphToMany(
            config('permission.models.permission'),
            'model',
            config('permission.table_names.model_has_permissions'),
            config('permission.column_names.model_morph_key'),
            'permission_id'
        )->withPivot('context_type', 'context_id');
    }

    /**
     * Scope the model query to certain permissions only.
     *
     * @param \Illuminate\Database\Eloquent\Builder $query
     * @param string|array|\Spatie\Permission\Contracts\Permission|\Illuminate\Support\Collection $permissions
     *
     * @return \Illuminate\Database\Eloquent\Builder
     */
    public function scopePermission(Builder $query, $permissions): Builder
    {
        $permissions = $this->convertToPermissionModels($permissions);

        $rolesWithPermissions = array_unique(array_reduce($permissions, function ($result, $permission) {
            return array_merge($result, $permission->roles->all());
        }, []));

        return $query->where(function (Builder $query) use ($permissions, $rolesWithPermissions) {
            $query->whereHas('permissions', function (Builder $subQuery) use ($permissions) {
                $subQuery->whereIn(config('permission.table_names.permissions').'.id', \array_column($permissions, 'id'));
            });
            if (count($rolesWithPermissions) > 0) {
                $query->orWhereHas('roles', function (Builder $subQuery) use ($rolesWithPermissions) {
                    $subQuery->whereIn(config('permission.table_names.roles').'.id', \array_column($rolesWithPermissions, 'id'));
                });
            }
        });
    }

    /**
     * @param string|array|\Spatie\Permission\Contracts\Permission|\Illuminate\Support\Collection $permissions
     *
     * @return array
     */
    protected function convertToPermissionModels($permissions): array
    {
        if ($permissions instanceof Collection) {
            $permissions = $permissions->all();
        }

        $permissions = is_array($permissions) ? $permissions : [$permissions];

        return array_map(function ($permission) {
            if ($permission instanceof Permission) {
                return $permission;
            }

            return $this->getPermissionClass()->findByName($permission, $this->getDefaultGuardName());
        }, $permissions);
    }

    /**
     * Determine if the model may perform the given permission.
     *
     * @param string|int|\Spatie\Permission\Contracts\Permission $permission
     * @param string|null $guardName
     * @param Model|null $context
     *
     * @return bool
     */
    public function hasPermissionTo($permission, $guardName = null, ?Model $context = null): bool
    {
        if (config('permission.enable_wildcard_permission', false)) {
            return $this->hasWildcardPermission($permission, $guardName);
        }

        $permissionClass = $this->getPermissionClass();

        if (is_string($permission)) {
            $permission = $permissionClass->findByName(
                $permission,
                $guardName ?? $this->getDefaultGuardName()
            );
        }

        if (is_int($permission)) {
            $permission = $permissionClass->findById(
                $permission,
                $guardName ?? $this->getDefaultGuardName()
            );
        }

        if (! $permission instanceof Permission) {
            throw new PermissionDoesNotExist;
        }

        return $this->hasDirectPermission($permission, $context) || $this->hasPermissionViaRole($permission, $context);
    }

    /**
     * Validates a wildcard permission against all permissions of a user.
     *
     * @param string|int|\Spatie\Permission\Contracts\Permission $permission
     * @param string|null $guardName
     *
     * @return bool
     */
    protected function hasWildcardPermission($permission, $guardName = null): bool
    {
        $guardName = $guardName ?? $this->getDefaultGuardName();

        if (is_int($permission)) {
            $permission = $this->getPermissionClass()->findById($permission, $guardName);
        }

        if ($permission instanceof Permission) {
            $permission = $permission->name;
        }

        if (! is_string($permission)) {
            throw WildcardPermissionInvalidArgument::create();
        }

        foreach ($this->getAllPermissions() as $userPermission) {
            if ($guardName !== $userPermission->guard_name) {
                continue;
            }

            $userPermission = new WildcardPermission($userPermission->name);

            if ($userPermission->implies($permission)) {
                return true;
            }
        }

        return false;
    }

    /**
     * @deprecated since 2.35.0
     * @alias of hasPermissionTo()
     */
    public function hasUncachedPermissionTo($permission, $guardName = null): bool
    {
        return $this->hasPermissionTo($permission, $guardName);
    }

    /**
     * An alias to hasPermissionTo(), but avoids throwing an exception.
     *
     * @param string|int|\Spatie\Permission\Contracts\Permission $permission
     * @param string|null $guardName
     * @param Model|null $context
     *
     * @return bool
     */
    public function checkPermissionTo($permission, $guardName = null, ?Model $context = null): bool
    {
        try {
            return $this->hasPermissionTo($permission, $guardName, $context);
        } catch (PermissionDoesNotExist $e) {
            return false;
        }
    }

    /**
     * Determine if the model has any of the given permissions.
     *
     * @param mixed $permissions
     * @param Model|null $context
     *
     * @return bool
     */
    public function hasAnyPermission($permissions, ?Model $context = null): bool
    {
        $permissions = collect(Arr::wrap($permissions))->flatten();

        foreach ($permissions as $permission) {
            if ($this->checkPermissionTo($permission, null, $context)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Determine if the model has all of the given permissions.
     *
     * @param mixed $permissions
     * @param Model|null $context
     *
     * @return bool
     */
    public function hasAllPermissions($permissions, ?Model $context = null): bool
    {
        $permissions = collect(Arr::wrap($permissions))->flatten();

        foreach ($permissions as $permission) {
            if (! $this->hasPermissionTo($permission, $context)) {
                return false;
            }
        }

        return true;
    }

    /**
     * Determine if the model has, via roles, the given permission.
     *
     * @param \Spatie\Permission\Contracts\Permission $permission
     * @param Model|null $context
     *
     * @return bool
     */
    protected function hasPermissionViaRole(Permission $permission, ?Model $context = null): bool
    {
        return $this->hasRole($permission->roles, null, $context);
    }

    /**
     * Determine if the model has the given permission.
     *
     * @param string|int|\Spatie\Permission\Contracts\Permission $permission
     * @param Model|null $context
     *
     * @return bool
     */
    public function hasDirectPermission($permission, ?Model $context = null): bool
    {
        $permissionClass = $this->getPermissionClass();

        if (is_string($permission)) {
            $permission = $permissionClass->findByName($permission, $this->getDefaultGuardName());
        }

        if (is_int($permission)) {
            $permission = $permissionClass->findById($permission, $this->getDefaultGuardName());
        }

        if (! $permission instanceof Permission) {
            throw new PermissionDoesNotExist;
        }

        $permissions = $this->permissions->filter(function ($el) use ($context) {
            $hasNotContext = $el->pivot->context_type === null && $el->pivot->context_id === null;
            $hasThisContext = $context && $el->pivot->context_type === get_class($context) && intval($el->pivot->context_id) === intval($context->id);
            return $hasNotContext || $hasThisContext;
        });

        return $permissions->contains('id', $permission->id);
    }

    /**
     * Return all the permissions the model has via roles.
     *
     * @param Model|null $context
     * @return Collection
     */
    public function getPermissionsViaRoles(?Model $context = null): Collection
    {
        $rolesQuery = $this->roles();

        if ($this->permissions()->getTable() === config('permission.table_names.model_has_permissions')) {
            $rolesQuery->where(
                function ($query) use ($context) {
                    $query->where(
                        function ($query) {
                            $query->whereNull('context_id');
                            $query->whereNull('context_type');
                        }
                    );
                    if ($context) {
                        $query->orWhere(
                            function (Builder $query) use ($context) {
                                $query->where('context_type', get_class($context));
                                $query->where('context_id', $context->id);
                            }
                        );
                    }
                }
            );
        }
        $roles = $rolesQuery->get();

        return $roles->flatMap(function ($role) {
                return $role->permissions;
            })->sort()->values();
    }

    /**
     * Return all the permissions the model has, both directly and via roles.
     *
     * @param Model|null $context
     * @return Collection
     */
    public function getAllPermissions(?Model $context = null): Collection
    {
        $permissionsQuery = $this->permissions();

        if ($this->permissions()->getTable() === config('permission.table_names.model_has_permissions')) {
            $permissionsQuery->where(
                function ($query) use ($context) {
                    $query->where(
                        function ($query) {
                            $query->whereNull('context_id');
                            $query->whereNull('context_type');
                        }
                    );
                    if ($context) {
                        $query->orWhere(
                            function (Builder $query) use ($context) {
                                $query->where('context_type', get_class($context));
                                $query->where('context_id', $context->id);
                            }
                        );
                    }
                }
            );
        }
        $permissions = $permissionsQuery->get();

        if ($this->roles) {
            $permissions = $permissions->merge($this->getPermissionsViaRoles($context));
        }

        return $permissions->sort()->values();
    }

    /**
     * Grant the given permission(s) to a role.
     *
     * @param string|array|\Spatie\Permission\Contracts\Permission|\Illuminate\Support\Collection $permissions
     * @param Model|null $context
     *
     * @return $this
     * @throws \Exception
     */
    public function givePermissionTo($permissions, ?Model $context = null)
    {
        if ($this->permissions()->getTable() === config('permission.table_names.role_has_permissions') && $context) {
            throw new \Exception('This relationship has no context support');
        }

        $permissions = collect(Arr::wrap($permissions))
            ->flatten()
            ->map(function ($permission) {
                if (empty($permission)) {
                    return false;
                }

                return $this->getStoredPermission($permission);
            })
            ->filter(function ($permission) {
                return $permission instanceof Permission;
            })
            ->each(function ($permission) {
                $this->ensureModelSharesGuard($permission);
            })
            ->map->id;

        if ($context) {
            $permissions = $permissions->mapWithKeys(function ($id) use ($context) {
                return [$id => [
                    'context_type' => get_class($context),
                    'context_id' => $context->id,
                ]];
            });
        }

        $permissions = $permissions->all();

        $model = $this->getModel();

        if ($model->exists) {
            $this->syncPermissionsWithoutDetaching($permissions, $model, $context);
        } else {
            $class = \get_class($model);

            $class::saved(
                function ($object) use ($permissions, $model, $context) {
                    $this->syncPermissionsWithoutDetaching($permissions, $object, $context);
                }
            );
        }

        $this->forgetCachedPermissions();

        return $this;
    }

    /**
     * Remove all current permissions and set the given ones.
     *
     * @param string|array|\Spatie\Permission\Contracts\Permission|\Illuminate\Support\Collection $permissions
     * @param Model|null $context
     *
     * @return $this
     */
    public function syncPermissions($permissions, ?Model $context = null)
    {
        $belongsToMany = $this->permissions();
        if ($this->permissions()->getTable() === config('permission.table_names.model_has_permissions')) {
            if ($context) {
            $belongsToMany->wherePivot('context_type', get_class($context))
                ->wherePivot('context_id', $context->id);
            } else {
            $belongsToMany->wherePivotNull('context_type')
                ->wherePivotNull('context_id');
            }
        }
        $belongsToMany->detach();

        return $this->givePermissionTo($permissions, $context);
    }

    /**
     * Revoke the given permission.
     *
     * @param \Spatie\Permission\Contracts\Permission|\Spatie\Permission\Contracts\Permission[]|string|string[] $permission
     * @param Model|null $context
     *
     * @return $this
     */
    public function revokePermissionTo($permission, ?Model $context = null)
    {
        $belongsToMany = $this->permissions();
        if ($this->permissions()->getTable() === config('permission.table_names.model_has_permissions')) {
            if ($context) {
            $belongsToMany->wherePivot('context_type', get_class($context))
                ->wherePivot('context_id', $context->id);
            } else {
            $belongsToMany->wherePivotNull('context_type')
                ->wherePivotNull('context_id');
            }
        }
        $belongsToMany->detach($this->getStoredPermission($permission));

        $this->forgetCachedPermissions();

        $this->load('permissions');

        return $this;
    }

    public function getPermissionNames(): Collection
    {
        return $this->permissions->pluck('name');
    }

    /**
     * @param string|array|\Spatie\Permission\Contracts\Permission|\Illuminate\Support\Collection $permissions
     *
     * @return \Spatie\Permission\Contracts\Permission|\Spatie\Permission\Contracts\Permission[]|\Illuminate\Support\Collection
     */
    protected function getStoredPermission($permissions)
    {
        $permissionClass = $this->getPermissionClass();

        if (is_numeric($permissions)) {
            return $permissionClass->findById($permissions, $this->getDefaultGuardName());
        }

        if (is_string($permissions)) {
            return $permissionClass->findByName($permissions, $this->getDefaultGuardName());
        }

        if (is_array($permissions)) {
            return $permissionClass
                ->whereIn('name', $permissions)
                ->whereIn('guard_name', $this->getGuardNames())
                ->get();
        }

        return $permissions;
    }

    /**
     * @param \Spatie\Permission\Contracts\Permission|\Spatie\Permission\Contracts\Role $roleOrPermission
     *
     * @throws \Spatie\Permission\Exceptions\GuardDoesNotMatch
     */
    protected function ensureModelSharesGuard($roleOrPermission)
    {
        if (! $this->getGuardNames()->contains($roleOrPermission->guard_name)) {
            throw GuardDoesNotMatch::create($roleOrPermission->guard_name, $this->getGuardNames());
        }
    }

    protected function getGuardNames(): Collection
    {
        return Guard::getNames($this);
    }

    protected function getDefaultGuardName(): string
    {
        return Guard::getDefaultName($this);
    }

    /**
     * Forget the cached permissions.
     */
    public function forgetCachedPermissions()
    {
        app(PermissionRegistrar::class)->forgetCachedPermissions();
    }

    /**
     * Check if the model has All of the requested Direct permissions.
     * @param array $permissions
     * @return bool
     */
    public function hasAllDirectPermissions($permissions): bool
    {
        $permissions = collect(Arr::wrap($permissions))->flatten();

        foreach ($permissions as $permission) {
            if (! $this->hasDirectPermission($permission)) {
                return false;
            }
        }

        return true;
    }

    /**
     * Check if the model has Any of the requested Direct permissions.
     * @param mixed $permissions
     * @param Model|null $context
     * @return bool
     */
    public function hasAnyDirectPermission($permissions, ?Model $context = null): bool
    {
        $permissions = collect(Arr::wrap($permissions))->flatten();

        foreach ($permissions as $permission) {
            if ($this->hasDirectPermission($permission, $context)) {
                return true;
            }
        }

        return false;
    }

    private function syncPermissionsWithoutDetaching($permissions, $model, $context = null): void
    {
        $belongsToMany = $this->permissions();
        if ($context) {
        $belongsToMany->wherePivot('context_type', get_class($context))
            ->wherePivot('context_id', $context->id);
        } else {
        $belongsToMany->wherePivotNull('context_type')
            ->wherePivotNull('context_id');
        }
        $belongsToMany->sync($permissions, false);
        $model->load('permissions');
    }
}
