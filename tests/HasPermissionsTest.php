<?php

namespace Spatie\Permission\Test;

use Spatie\Permission\Contracts\Permission;
use Spatie\Permission\Contracts\Role;
use Spatie\Permission\Exceptions\GuardDoesNotMatch;
use Spatie\Permission\Exceptions\PermissionDoesNotExist;

class HasPermissionsTest extends TestCase
{
    /** @test */
    public function it_can_assign_a_permission_to_a_user()
    {
        $this->testUser->givePermissionTo($this->testUserPermission);

        $this->assertTrue($this->testUser->hasPermissionTo($this->testUserPermission));
    }

    /** @test */
    public function it_can_assign_a_permission_to_a_user_using_context()
    {
        $context = Team::create();
        $wrongContext = Team::create();
        $this->testUser->givePermissionTo($this->testUserPermission, $context);

        $this->assertFalse($this->testUser->hasPermissionTo($this->testUserPermission));
        $this->assertTrue($this->testUser->hasPermissionTo($this->testUserPermission, null, $context));
        $this->assertFalse($this->testUser->hasPermissionTo($this->testUserPermission, null, $wrongContext));
    }

    /** @test */
    public function it_can_assign_a_permission_to_a_user_using_context_and_role()
    {
        $context = Team::create();
        $wrongContext = Team::create();
        $this->testUserRole->givePermissionTo($this->testUserPermission);
        $this->testUser->assignRole($this->testUserRole, $context);

        $this->assertFalse($this->testUser->hasPermissionTo($this->testUserPermission));
        $this->assertTrue($this->testUser->hasPermissionTo($this->testUserPermission, null, $context));
        $this->assertFalse($this->testUser->hasPermissionTo($this->testUserPermission, null, $wrongContext));
    }

    /** @test */
    public function it_can_assign_the_same_permission_to_a_user_using_different_contexts()
    {
        $contextA = Team::create();
        $contextB = Team::create();
        $this->testUser->givePermissionTo($this->testUserPermission, $contextA);
        $this->testUser->givePermissionTo($this->testUserPermission, $contextB);

        $this->assertFalse($this->testUser->hasPermissionTo($this->testUserPermission));
        $this->assertTrue($this->testUser->hasPermissionTo($this->testUserPermission, null, $contextA));
        $this->assertTrue($this->testUser->hasPermissionTo($this->testUserPermission, null, $contextB));
    }

    /** @test */
    public function it_can_sync_permissions_to_a_user_using_different_contexts()
    {
        $contextA = Team::create();
        $contextB = Team::create();

        $this->testUser->syncPermissions(['edit-articles', 'edit-blog'], $contextA);
        $this->testUser->syncPermissions(['edit-news', 'edit-blog'], $contextB);

        $this->assertTrue($this->testUser->hasDirectPermission('edit-articles', $contextA));
        $this->assertTrue($this->testUser->hasDirectPermission('edit-blog', $contextA));
        $this->assertFalse($this->testUser->hasDirectPermission('edit-news', $contextA));

        $this->assertFalse($this->testUser->hasDirectPermission('edit-articles', $contextB));
        $this->assertTrue($this->testUser->hasDirectPermission('edit-blog', $contextB));
        $this->assertTrue($this->testUser->hasDirectPermission('edit-news', $contextB));
    }

    /** @test */
    public function it_can_assign_the_same_permission_to_a_user_using_global_context()
    {
        $contextA = Team::create();
        $this->testUser->givePermissionTo($this->testUserPermission);
        $this->testUser->givePermissionTo($this->testUserPermission, $contextA);

        $this->assertEquals(2, $this->testUser->permissions()->count());
        $this->assertTrue($this->testUser->hasPermissionTo($this->testUserPermission));
        $this->assertTrue($this->testUser->hasPermissionTo($this->testUserPermission, null, $contextA));
    }

    /** @test */
    public function it_can_sync_multiple_permissions_using_context()
    {
        $context = Team::create();
        $this->testUser->givePermissionTo('edit-news', $context);

        $this->testUser->syncPermissions(['edit-articles', 'edit-blog'], $context);

        $this->assertFalse($this->testUser->hasDirectPermission('edit-articles'));
        $this->assertFalse($this->testUser->hasDirectPermission('edit-blog'));
        $this->assertFalse($this->testUser->hasDirectPermission('edit-news'));

        $this->assertTrue($this->testUser->hasDirectPermission('edit-articles', $context));
        $this->assertTrue($this->testUser->hasDirectPermission('edit-blog', $context));
        $this->assertFalse($this->testUser->hasDirectPermission('edit-news', $context));
    }

    /** @test */
    public function it_wont_sync_permissions_from_global_context()
    {
        $context = Team::create();
        $this->testUser->givePermissionTo('edit-news');

        $this->testUser->syncPermissions(['edit-articles', 'edit-blog'], $context);

        $this->assertFalse($this->testUser->hasDirectPermission('edit-articles'));
        $this->assertFalse($this->testUser->hasDirectPermission('edit-blog'));
        $this->assertTrue($this->testUser->hasDirectPermission('edit-news'));

        $this->assertTrue($this->testUser->hasDirectPermission('edit-articles', $context));
        $this->assertTrue($this->testUser->hasDirectPermission('edit-blog', $context));
        $this->assertTrue($this->testUser->hasDirectPermission('edit-news', $context));
    }

    /** @test */
    public function it_wont_sync_permissions_from_another_context()
    {
        $context = Team::create();
        $this->testUser->givePermissionTo('edit-news', $context);

        $this->testUser->syncPermissions(['edit-articles', 'edit-blog']);

        $this->assertTrue($this->testUser->hasDirectPermission('edit-articles'));
        $this->assertTrue($this->testUser->hasDirectPermission('edit-blog'));
        $this->assertFalse($this->testUser->hasDirectPermission('edit-news'));

        $this->assertTrue($this->testUser->hasDirectPermission('edit-articles', $context));
        $this->assertTrue($this->testUser->hasDirectPermission('edit-blog', $context));
        $this->assertTrue($this->testUser->hasDirectPermission('edit-news', $context));
    }

    /** @test */
    public function it_throws_an_exception_when_assigning_a_permission_that_does_not_exist()
    {
        $this->expectException(PermissionDoesNotExist::class);

        $this->testUser->givePermissionTo('permission-does-not-exist');
    }

    /** @test */
    public function it_throws_an_exception_when_assigning_a_permission_to_a_user_from_a_different_guard()
    {
        $this->expectException(GuardDoesNotMatch::class);

        $this->testUser->givePermissionTo($this->testAdminPermission);

        $this->expectException(PermissionDoesNotExist::class);

        $this->testUser->givePermissionTo('admin-permission');
    }

    /** @test */
    public function it_can_revoke_a_permission_from_a_user()
    {
        $this->testUser->givePermissionTo($this->testUserPermission);

        $this->assertTrue($this->testUser->hasPermissionTo($this->testUserPermission));

        $this->testUser->revokePermissionTo($this->testUserPermission);

        $this->assertFalse($this->testUser->hasPermissionTo($this->testUserPermission));
    }

    /** @test */
    public function it_can_revoke_a_permission_from_a_user_using_global_context()
    {
        $context = Team::create();
        $this->testUser->givePermissionTo('edit-news');
        $this->testUser->givePermissionTo('edit-news', $context);

        $this->testUser->revokePermissionTo('edit-news');

        $this->assertEquals(1, $this->testUser->permissions()->count());
        $this->assertFalse($this->testUser->hasDirectPermission('edit-news'));
        $this->assertTrue($this->testUser->hasDirectPermission('edit-news', $context));
    }

    /** @test */
    public function it_can_revoke_a_permission_from_a_user_using_context()
    {
        $context = Team::create();
        $this->testUser->givePermissionTo('edit-news');
        $this->testUser->givePermissionTo('edit-news', $context);

        $this->testUser->revokePermissionTo('edit-news', $context);

        $this->assertEquals(1, $this->testUser->permissions()->count());
        $this->assertTrue($this->testUser->hasDirectPermission('edit-news'));
        $this->assertTrue($this->testUser->hasDirectPermission('edit-news', $context));
    }

    /** @test */
    public function it_can_revoke_a_permission_from_a_user_using_different_contexts()
    {
        $contextA = Team::create();
        $contextB = Team::create();
        $this->testUser->givePermissionTo('edit-news', $contextA);
        $this->testUser->givePermissionTo('edit-news', $contextB);

        $this->testUser->revokePermissionTo('edit-news', $contextA);

        $this->assertEquals(1, $this->testUser->permissions()->count());
        $this->assertFalse($this->testUser->hasDirectPermission('edit-news', $contextA));
        $this->assertTrue($this->testUser->hasDirectPermission('edit-news', $contextB));
    }

    /** @test */
    public function it_can_scope_users_using_a_string()
    {
        $user1 = User::create(['email' => 'user1@test.com']);
        $user2 = User::create(['email' => 'user2@test.com']);
        $user1->givePermissionTo(['edit-articles', 'edit-news']);
        $this->testUserRole->givePermissionTo('edit-articles');
        $user2->assignRole('testRole');

        $scopedUsers1 = User::permission('edit-articles')->get();
        $scopedUsers2 = User::permission(['edit-news'])->get();

        $this->assertEquals(2, $scopedUsers1->count());
        $this->assertEquals(1, $scopedUsers2->count());
    }

    /** @test */
    public function it_can_scope_users_using_an_array()
    {
        $user1 = User::create(['email' => 'user1@test.com']);
        $user2 = User::create(['email' => 'user2@test.com']);
        $user1->givePermissionTo(['edit-articles', 'edit-news']);
        $this->testUserRole->givePermissionTo('edit-articles');
        $user2->assignRole('testRole');

        $scopedUsers1 = User::permission(['edit-articles', 'edit-news'])->get();
        $scopedUsers2 = User::permission(['edit-news'])->get();

        $this->assertEquals(2, $scopedUsers1->count());
        $this->assertEquals(1, $scopedUsers2->count());
    }

    /** @test */
    public function it_can_scope_users_using_a_collection()
    {
        $user1 = User::create(['email' => 'user1@test.com']);
        $user2 = User::create(['email' => 'user2@test.com']);
        $user1->givePermissionTo(['edit-articles', 'edit-news']);
        $this->testUserRole->givePermissionTo('edit-articles');
        $user2->assignRole('testRole');

        $scopedUsers1 = User::permission(collect(['edit-articles', 'edit-news']))->get();
        $scopedUsers2 = User::permission(collect(['edit-news']))->get();

        $this->assertEquals(2, $scopedUsers1->count());
        $this->assertEquals(1, $scopedUsers2->count());
    }

    /** @test */
    public function it_can_scope_users_using_an_object()
    {
        $user1 = User::create(['email' => 'user1@test.com']);
        $user1->givePermissionTo($this->testUserPermission->name);

        $scopedUsers1 = User::permission($this->testUserPermission)->get();
        $scopedUsers2 = User::permission([$this->testUserPermission])->get();
        $scopedUsers3 = User::permission(collect([$this->testUserPermission]))->get();

        $this->assertEquals(1, $scopedUsers1->count());
        $this->assertEquals(1, $scopedUsers2->count());
        $this->assertEquals(1, $scopedUsers3->count());
    }

    /** @test */
    public function it_can_scope_users_without_permissions_only_role()
    {
        $user1 = User::create(['email' => 'user1@test.com']);
        $user2 = User::create(['email' => 'user2@test.com']);
        $this->testUserRole->givePermissionTo('edit-articles');
        $user1->assignRole('testRole');
        $user2->assignRole('testRole');

        $scopedUsers = User::permission('edit-articles')->get();

        $this->assertEquals(2, $scopedUsers->count());
    }

    /** @test */
    public function it_can_scope_users_without_permissions_only_permission()
    {
        $user1 = User::create(['email' => 'user1@test.com']);
        $user2 = User::create(['email' => 'user2@test.com']);
        $user1->givePermissionTo(['edit-news']);
        $user2->givePermissionTo(['edit-articles', 'edit-news']);

        $scopedUsers = User::permission('edit-news')->get();

        $this->assertEquals(2, $scopedUsers->count());
    }

    /** @test */
    public function it_throws_an_exception_when_calling_hasPermissionTo_with_an_invalid_type()
    {
        $user = User::create(['email' => 'user1@test.com']);

        $this->expectException(PermissionDoesNotExist::class);

        $user->hasPermissionTo(new \stdClass());
    }

    /** @test */
    public function it_throws_an_exception_when_calling_hasPermissionTo_with_null()
    {
        $user = User::create(['email' => 'user1@test.com']);

        $this->expectException(PermissionDoesNotExist::class);

        $user->hasPermissionTo(null);
    }

    /** @test */
    public function it_throws_an_exception_when_calling_hasDirectPermission_with_an_invalid_type()
    {
        $user = User::create(['email' => 'user1@test.com']);

        $this->expectException(PermissionDoesNotExist::class);

        $user->hasDirectPermission(new \stdClass());
    }

    /** @test */
    public function it_throws_an_exception_when_calling_hasDirectPermission_with_null()
    {
        $user = User::create(['email' => 'user1@test.com']);

        $this->expectException(PermissionDoesNotExist::class);

        $user->hasDirectPermission(null);
    }

    /** @test */
    public function it_throws_an_exception_when_trying_to_scope_a_non_existing_permission()
    {
        $this->expectException(PermissionDoesNotExist::class);

        User::permission('not defined permission')->get();
    }

    /** @test */
    public function it_throws_an_exception_when_trying_to_scope_a_permission_from_another_guard()
    {
        $this->expectException(PermissionDoesNotExist::class);

        User::permission('testAdminPermission')->get();

        $this->expectException(GuardDoesNotMatch::class);

        User::permission($this->testAdminPermission)->get();
    }

    /** @test */
    public function it_doesnt_detach_permissions_when_soft_deleting()
    {
        $user = SoftDeletingUser::create(['email' => 'test@example.com']);
        $user->givePermissionTo(['edit-news']);
        $user->delete();

        $user = SoftDeletingUser::withTrashed()->find($user->id);

        $this->assertTrue($user->hasPermissionTo('edit-news'));
    }

    /** @test */
    public function it_can_give_and_revoke_multiple_permissions()
    {
        $this->testUserRole->givePermissionTo(['edit-articles', 'edit-news']);

        $this->assertEquals(2, $this->testUserRole->permissions()->count());

        $this->testUserRole->revokePermissionTo(['edit-articles', 'edit-news']);

        $this->assertEquals(0, $this->testUserRole->permissions()->count());
    }

    /** @test */
    public function it_can_determine_that_the_user_does_not_have_a_permission()
    {
        $this->assertFalse($this->testUser->hasPermissionTo('edit-articles'));
    }

    /** @test */
    public function it_throws_an_exception_when_the_permission_does_not_exist()
    {
        $this->expectException(PermissionDoesNotExist::class);

        $this->testUser->hasPermissionTo('does-not-exist');
    }

    /** @test */
    public function it_throws_an_exception_when_the_permission_does_not_exist_for_this_guard()
    {
        $this->expectException(PermissionDoesNotExist::class);

        $this->testUser->hasPermissionTo('does-not-exist', 'web');
    }

    /** @test */
    public function it_can_reject_a_user_that_does_not_have_any_permissions_at_all()
    {
        $user = new User();

        $this->assertFalse($user->hasPermissionTo('edit-articles'));
    }

    /** @test */
    public function it_can_determine_that_the_user_has_any_of_the_permissions_directly()
    {
        $this->assertFalse($this->testUser->hasAnyPermission('edit-articles'));

        $this->testUser->givePermissionTo('edit-articles');

        $this->assertTrue($this->testUser->hasAnyPermission(['edit-news', 'edit-articles']));

        $this->testUser->givePermissionTo('edit-news');

        $this->testUser->revokePermissionTo($this->testUserPermission);

        $this->assertTrue($this->testUser->hasAnyPermission(['edit-articles', 'edit-news']));
        $this->assertFalse($this->testUser->hasAnyPermission(['edit-blog', 'Edit News', ['Edit News']]));
    }

    /** @test */
    public function it_can_determine_that_the_user_has_any_of_the_permissions_directly_using_an_array()
    {
        $this->assertFalse($this->testUser->hasAnyPermission(['edit-articles']));

        $this->testUser->givePermissionTo('edit-articles');

        $this->assertTrue($this->testUser->hasAnyPermission(['edit-news', 'edit-articles']));

        $this->testUser->givePermissionTo('edit-news');

        $this->testUser->revokePermissionTo($this->testUserPermission);

        $this->assertTrue($this->testUser->hasAnyPermission(['edit-articles', 'edit-news']));
    }

    /** @test */
    public function it_can_determine_that_the_user_has_any_of_the_permissions_via_role()
    {
        $this->testUserRole->givePermissionTo('edit-articles');

        $this->testUser->assignRole('testRole');

        $this->assertTrue($this->testUser->hasAnyPermission(['edit-news', 'edit-articles']));
        $this->assertFalse($this->testUser->hasAnyPermission(['edit-blog', 'Edit News', ['Edit News']]));
    }

    /** @test */
    public function it_can_determine_that_the_user_has_any_of_the_permissions_via_role_using_context()
    {
        $context = Team::create();
        $this->testUserRole->givePermissionTo('edit-articles');
        $this->testUser->assignRole('testRole', $context);

        $this->assertTrue($this->testUser->hasAnyPermission(['edit-news', 'edit-articles'], $context));
        $this->assertFalse($this->testUser->hasAnyPermission(['edit-blog', 'Edit News', ['Edit News']], $context));
        $this->assertFalse($this->testUser->hasAnyPermission(['edit-news', 'edit-articles']));
        $this->assertFalse($this->testUser->hasAnyPermission(['edit-blog', 'Edit News', ['Edit News']]));
    }

    /** @test */
    public function it_can_determine_that_the_user_has_all_of_the_permissions_directly()
    {
        $this->testUser->givePermissionTo(['edit-articles', 'edit-news']);

        $this->assertTrue($this->testUser->hasAllPermissions(['edit-articles', 'edit-news']));

        $this->testUser->revokePermissionTo('edit-articles');

        $this->assertFalse($this->testUser->hasAllPermissions(['edit-articles', 'edit-news']));
        $this->assertFalse($this->testUser->hasAllPermissions(['edit-articles', 'edit-news', 'edit-blog']));
    }

    /** @test */
    public function it_can_determine_that_the_user_has_all_of_the_permissions_directly_using_an_array()
    {
        $this->assertFalse($this->testUser->hasAllPermissions(['edit-articles', 'edit-news']));

        $this->testUser->revokePermissionTo('edit-articles');

        $this->assertFalse($this->testUser->hasAllPermissions(['edit-news', 'edit-articles']));

        $this->testUser->givePermissionTo('edit-news');

        $this->testUser->revokePermissionTo($this->testUserPermission);

        $this->assertFalse($this->testUser->hasAllPermissions(['edit-articles', 'edit-news']));
    }

    /** @test */
    public function it_can_determine_that_the_user_has_all_of_the_permissions_via_role()
    {
        $this->testUserRole->givePermissionTo(['edit-articles', 'edit-news']);

        $this->testUser->assignRole('testRole');

        $this->assertTrue($this->testUser->hasAllPermissions(['edit-articles', 'edit-news']));
    }

    /** @test */
    public function it_can_determine_that_user_has_direct_permission()
    {
        $context = Team::create();
        $wrongContext = Team::create();
        $this->testUser->givePermissionTo('edit-articles');
        $this->testUser->givePermissionTo('edit-blog', $context);
        $this->testUser->givePermissionTo('edit-news', $wrongContext);
        $this->assertTrue($this->testUser->hasDirectPermission('edit-articles', $context));
        $this->assertTrue($this->testUser->hasDirectPermission('edit-blog', $context));
        $this->assertFalse($this->testUser->hasDirectPermission('edit-news', $context));
        $this->assertEquals(
            collect(['edit-articles', 'edit-blog']),
            $this->testUser->getDirectPermissions($context)->pluck('name')
        );
    }

    /** @test */
    public function it_can_determine_that_user_has_direct_permission_using_context()
    {
        $this->testUser->givePermissionTo('edit-articles');
        $this->assertTrue($this->testUser->hasDirectPermission('edit-articles'));
        $this->assertEquals(
            collect(['edit-articles']),
            $this->testUser->getDirectPermissions()->pluck('name')
        );

        $this->testUser->revokePermissionTo('edit-articles');
        $this->assertFalse($this->testUser->hasDirectPermission('edit-articles'));

        $this->testUser->assignRole('testRole');
        $this->testUserRole->givePermissionTo('edit-articles');
        $this->assertFalse($this->testUser->hasDirectPermission('edit-articles'));
    }

    /** @test */
    public function it_can_list_all_the_permissions_via_roles_of_user()
    {
        $roleModel = app(Role::class);
        $roleModel->findByName('testRole2')->givePermissionTo('edit-news');

        $this->testUserRole->givePermissionTo('edit-articles');
        $this->testUser->assignRole(['testRole', 'testRole2']);

        $this->assertEquals(
            collect(['edit-articles', 'edit-news']),
            $this->testUser->getPermissionsViaRoles()->pluck('name')
        );
    }

    /** @test */
    public function it_can_use_global_permission_in_context()
    {
        $context = Team::create();
        $this->testUser->givePermissionTo('edit-news');

        $this->assertTrue($this->testUser->hasDirectPermission('edit-news'));
        $this->assertTrue($this->testUser->hasDirectPermission('edit-news', $context));
    }

    /** @test */
    public function it_can_list_all_the_coupled_permissions_both_directly_and_via_roles()
    {
        $this->testUser->givePermissionTo('edit-news');

        $this->testUserRole->givePermissionTo('edit-articles');
        $this->testUser->assignRole('testRole');

        $this->assertEquals(
            collect(['edit-articles', 'edit-news']),
            $this->testUser->getAllPermissions()->pluck('name')->sort()->values()
        );
    }

    /** @test */
    public function it_can_list_all_the_coupled_permissions_directly_using_context()
    {
        $context = Team::create();
        $wrongContext = Team::create();
        $this->testUser->givePermissionTo('edit-news');
        $this->testUser->givePermissionTo('edit-articles', $context);
        $this->testUser->givePermissionTo('edit-blog', $wrongContext);

        $this->assertEquals(
            collect(['edit-articles', 'edit-news']),
            $this->testUser->getAllPermissions($context)->pluck('name')->sort()->values()
        );
    }

    /** @test */
    public function it_can_list_all_the_coupled_permissions_both_directly_and_via_roles_using_context()
    {
        $context = Team::create();
        $wrongContext = Team::create();

        $this->testUserRole->givePermissionTo('edit-articles');
        $this->testUser->assignRole('testRole');

        app(Role::class)->findByName('testRole2', 'web')->givePermissionTo('edit-news');
        $this->testUser->assignRole('testRole2', $context);

        app(Role::class)->findByName('testRole3', 'web')->givePermissionTo('edit-blog');
        $this->testUser->assignRole('testRole3', $wrongContext);

        $this->assertEquals(
            collect(['edit-articles', 'edit-news']),
            $this->testUser->getAllPermissions($context)->pluck('name')->sort()->values()
        );
    }

    /** @test */
    public function it_can_sync_multiple_permissions()
    {
        $this->testUser->givePermissionTo('edit-news');

        $this->testUser->syncPermissions(['edit-articles', 'edit-blog']);

        $this->assertTrue($this->testUser->hasDirectPermission('edit-articles'));

        $this->assertTrue($this->testUser->hasDirectPermission('edit-blog'));

        $this->assertFalse($this->testUser->hasDirectPermission('edit-news'));
    }

    /** @test */
    public function it_can_sync_multiple_permissions_by_id()
    {
        $this->testUser->givePermissionTo('edit-news');

        $ids = app(Permission::class)::whereIn('name', ['edit-articles', 'edit-blog'])->pluck('id');

        $this->testUser->syncPermissions($ids);

        $this->assertTrue($this->testUser->hasDirectPermission('edit-articles'));

        $this->assertTrue($this->testUser->hasDirectPermission('edit-blog'));

        $this->assertFalse($this->testUser->hasDirectPermission('edit-news'));
    }

    /** @test */
    public function sync_permission_ignores_null_inputs()
    {
        $this->testUser->givePermissionTo('edit-news');

        $ids = app(Permission::class)::whereIn('name', ['edit-articles', 'edit-blog'])->pluck('id');

        $ids->push(null);

        $this->testUser->syncPermissions($ids);

        $this->assertTrue($this->testUser->hasDirectPermission('edit-articles'));

        $this->assertTrue($this->testUser->hasDirectPermission('edit-blog'));

        $this->assertFalse($this->testUser->hasDirectPermission('edit-news'));
    }

    /** @test */
    public function it_does_not_remove_already_associated_permissions_when_assigning_new_permissions()
    {
        $this->testUser->givePermissionTo('edit-news');

        $this->testUser->givePermissionTo('edit-articles');

        $this->assertTrue($this->testUser->fresh()->hasDirectPermission('edit-news'));
    }

    /** @test */
    public function it_does_not_throw_an_exception_when_assigning_a_permission_that_is_already_assigned()
    {
        $this->testUser->givePermissionTo('edit-news');

        $this->testUser->givePermissionTo('edit-news');

        $this->assertTrue($this->testUser->fresh()->hasDirectPermission('edit-news'));
    }

    /** @test */
    public function it_can_sync_permissions_to_a_model_that_is_not_persisted()
    {
        $user = new User(['email' => 'test@user.com']);
        $user->syncPermissions('edit-articles');
        $user->save();

        $this->assertTrue($user->hasPermissionTo('edit-articles'));

        $user->syncPermissions('edit-articles');
        $this->assertTrue($user->hasPermissionTo('edit-articles'));
        $this->assertTrue($user->fresh()->hasPermissionTo('edit-articles'));
    }

    /** @test */
    public function calling_givePermissionTo_before_saving_object_doesnt_interfere_with_other_objects()
    {
        $user = new User(['email' => 'test@user.com']);
        $user->givePermissionTo('edit-news');
        $user->save();

        $user2 = new User(['email' => 'test2@user.com']);
        $user2->givePermissionTo('edit-articles');
        $user2->save();

        $this->assertTrue($user->fresh()->hasPermissionTo('edit-news'));
        $this->assertFalse($user->fresh()->hasPermissionTo('edit-articles'));

        $this->assertTrue($user2->fresh()->hasPermissionTo('edit-articles'));
        $this->assertFalse($user2->fresh()->hasPermissionTo('edit-news'));
    }

    /** @test */
    public function calling_syncPermissions_before_saving_object_doesnt_interfere_with_other_objects()
    {
        $user = new User(['email' => 'test@user.com']);
        $user->syncPermissions('edit-news');
        $user->save();

        $user2 = new User(['email' => 'test2@user.com']);
        $user2->syncPermissions('edit-articles');
        $user2->save();

        $this->assertTrue($user->fresh()->hasPermissionTo('edit-news'));
        $this->assertFalse($user->fresh()->hasPermissionTo('edit-articles'));

        $this->assertTrue($user2->fresh()->hasPermissionTo('edit-articles'));
        $this->assertFalse($user2->fresh()->hasPermissionTo('edit-news'));
    }

    /** @test */
    public function it_can_retrieve_permission_names()
    {
        $this->testUser->givePermissionTo(['edit-news', 'edit-articles']);
        $this->assertEquals(
            collect(['edit-news', 'edit-articles']),
            $this->testUser->getPermissionNames()
        );
    }

    /** @test */
    public function it_can_check_many_direct_permissions()
    {
        $this->testUser->givePermissionTo(['edit-articles', 'edit-news']);
        $this->assertTrue($this->testUser->hasAllDirectPermissions(['edit-news', 'edit-articles']));
        $this->assertTrue($this->testUser->hasAllDirectPermissions('edit-news', 'edit-articles'));
        $this->assertFalse($this->testUser->hasAllDirectPermissions(['edit-articles', 'edit-news', 'edit-blog']));
        $this->assertFalse($this->testUser->hasAllDirectPermissions([['edit-articles', 'edit-news'], 'edit-blog']));
    }

    /** @test */
    public function it_can_check_if_there_is_any_of_the_direct_permissions_given()
    {
        $this->testUser->givePermissionTo(['edit-articles', 'edit-news']);
        $this->assertTrue($this->testUser->hasAnyDirectPermission(['edit-news', 'edit-blog']));
        $this->assertTrue($this->testUser->hasAnyDirectPermission(['edit-news', 'edit-blog']));
        $this->assertFalse($this->testUser->hasAnyDirectPermission(['edit-blog', 'Edit News', ['Edit News']]));
    }

    /** @test */
    public function it_can_filter_users_who_have_any_of_the_permissions_directly()
    {
        $this->assertCount(0, User::whereHasAnyPermissionForContext(['edit-articles'], null)->get());

        $this->testUser->givePermissionTo('edit-articles');

        $this->assertCount(1, User::whereHasAnyPermissionForContext(['edit-articles', 'edit-news'], null)->get());

        $this->testUser->givePermissionTo('edit-news');
        $this->testUser->revokePermissionTo($this->testUserPermission);

        $this->assertCount(1, User::whereHasAnyPermissionForContext(['edit-articles', 'edit-news'], null)->get());
        $this->assertCount(0, User::whereHasAnyPermissionForContext(['edit-blog', 'Edit News', 'Edit News'], null)->get());
    }

    /** @test */
    public function it_can_filter_users_who_have_any_of_the_permissions_directly_using_context()
    {
        $context = Team::create();
        $this->assertCount(0, User::whereHasAnyPermissionForContext(['edit-articles', 'edit-news'], null)->get());

        $this->testUser->givePermissionTo('edit-articles');
        $this->testUser->givePermissionTo('edit-news', $context);

        $this->assertCount(1, User::whereHasAnyPermissionForContext(['edit-articles', 'edit-news'], null)->get());
        $this->assertCount(1, User::whereHasAnyPermissionForContext(['edit-articles'], null)->get());
        $this->assertCount(0, User::whereHasAnyPermissionForContext(['edit-news'], null)->get());
        $this->assertCount(1, User::whereHasAnyPermissionForContext(['edit-articles', 'edit-news'], $context)->get());
        $this->assertCount(1, User::whereHasAnyPermissionForContext(['edit-articles'], $context)->get());
        $this->assertCount(1, User::whereHasAnyPermissionForContext(['edit-news'], $context)->get());
    }

    /** @test */
    public function it_can_filter_users_who_have_any_of_the_permissions_via_role()
    {
        $this->testUserRole->givePermissionTo('edit-articles');

        $this->testUser->assignRole('testRole');

        $this->assertCount(1, User::whereHasAnyPermissionForContext(['edit-news', 'edit-articles'], null)->get());
        $this->assertCount(0, User::whereHasAnyPermissionForContext(['edit-blog', 'Edit News', 'Edit News'], null)->get());
    }

    /** @test */
    public function it_can_filter_users_who_have_any_of_the_permissions_via_role_using_context()
    {
        $context = Team::create();
        $this->testUserRole->givePermissionTo('edit-articles');
        $this->testUser->assignRole('testRole', $context);

        $this->assertCount(1, User::whereHasAnyPermissionForContext(['edit-news', 'edit-articles'], $context)->get());
        $this->assertCount(0, User::whereHasAnyPermissionForContext(['edit-blog', 'Edit News', 'Edit News'], $context)->get());
        $this->assertCount(0, User::whereHasAnyPermissionForContext(['edit-news', 'edit-articles'], null)->get());
        $this->assertCount(0, User::whereHasAnyPermissionForContext(['edit-blog', 'Edit News', 'Edit News'], null)->get());
    }

    /** @test */
    public function it_can_filter_users_who_have_all_of_the_permissions_directly()
    {
        $this->assertCount(0, User::whereHasAllPermissionForContext(['edit-articles'], null)->get());

        $this->testUser->givePermissionTo('edit-articles');

        $this->assertCount(1, User::whereHasAllPermissionForContext(['edit-articles'], null)->get());
        $this->assertCount(0, User::whereHasAllPermissionForContext(['edit-articles', 'edit-news'], null)->get());
    }

    /** @test */
    public function it_can_filter_users_who_have_all_of_the_permissions_directly_using_context()
    {
        $context = Team::create();
//        $this->assertCount(0, User::whereHasAllPermissionForContext(['edit-articles', 'edit-news'], null)->get());

        $this->testUser->givePermissionTo('edit-articles');
        $this->testUser->givePermissionTo('edit-news', $context);

//        $this->assertCount(1, User::whereHasAllPermissionForContext(['edit-articles'], null)->get());
//        $this->assertCount(0, User::whereHasAllPermissionForContext(['edit-news'], null)->get());
//        $this->assertCount(0, User::whereHasAllPermissionForContext(['edit-articles', 'edit-news'], null)->get());
        $this->assertCount(1, User::whereHasAllPermissionForContext(['edit-articles'], $context)->get());
        $this->assertCount(1, User::whereHasAllPermissionForContext(['edit-news'], $context)->get());
        $this->assertCount(1, User::whereHasAllPermissionForContext(['edit-articles', 'edit-news'], $context)->get());
    }

    /** @test */
    public function it_can_filter_users_who_have_all_of_the_permissions_via_role()
    {
        $this->testUserRole->givePermissionTo('edit-articles');

        $this->testUser->assignRole('testRole');

        $this->assertCount(1, User::whereHasAllPermissionForContext(['edit-articles'], null)->get());
        $this->assertCount(0, User::whereHasAllPermissionForContext(['edit-news', 'edit-articles'], null)->get());
    }

    /** @test */
    public function it_can_filter_users_who_have_all_of_the_permissions_via_role_using_context()
    {
        $context = Team::create();
        $this->testUserRole->givePermissionTo('edit-articles');
        $this->testUser->assignRole('testRole', $context);

        $this->assertCount(1, User::whereHasAllPermissionForContext(['edit-articles'], $context)->get());
        $this->assertCount(0, User::whereHasAllPermissionForContext(['edit-news', 'edit-articles'], $context)->get());
        $this->assertCount(0, User::whereHasAllPermissionForContext(['edit-articles'], null)->get());
        $this->assertCount(0, User::whereHasAllPermissionForContext(['edit-news', 'edit-articles'], null)->get());
    }
}
