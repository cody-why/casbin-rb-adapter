use casbin::{CoreApi, Enforcer};
use casbin::{RbacApi, Result};
use rbatis::RBatis;
use casbin_rb_adapter::{to_vec, RbatisAdapter};
use rbdc_mysql::driver::MysqlDriver;

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::init();
    let url = include_str!("../.env").trim_start_matches("DATABASE_URL=");

    let rb = RBatis::new();
    rb.init(MysqlDriver {}, url).unwrap();
    
    let adapter = RbatisAdapter::new(&rb).await?;
    // need to call db_sync() to create tables in database
    // adapter.db_sync().await?;

    let mut e = Enforcer::new("examples/rbac_model.conf", adapter).await?;

    e.clear_policy().await.unwrap();

    e.add_permission_for_user("admin", to_vec!["data1", "read"]).await
        .unwrap_or_else(|e|{
            println!("add permission error: {}", e);
            false
        });

    let permissions = e.get_permissions_for_user("admin", None);
    println!("permissions: {:?}",permissions);
    assert!(!permissions.is_empty());

    // test delete permission
    e.delete_permission_for_user("admin", to_vec!["data1", "read"]).await.unwrap();
    // e.delete_permissions_for_user("admin").await.unwrap();

    let permissions = e.get_permissions_for_user("admin", None);
    println!("permissions: {:?}",permissions);
    assert!(permissions.is_empty());

    e.add_permission_for_user("admin", to_vec!["data1", "write"]).await
        .unwrap_or_else(|e|{
            println!("add permission error: {}", e);
            false
    });
    e.add_permission_for_user("admin", to_vec!["data1", "read"]).await
        .unwrap_or_else(|e|{
            println!("add permission error: {}", e);
            false
    });
    e.add_permission_for_user("user", to_vec!["data1", "read"]).await
    .unwrap_or_else(|e|{
        println!("add permission error: {}", e);
        false
    });

    e.add_role_for_user("alice", "admin", None).await.unwrap();

    let roles = e.get_roles_for_user("alice", None);
    println!("get_roles_for_user alice: {:?}", roles);

    let sub = "alice"; // the user
    let obj = "data1"; // the resource
    let act = "read"; // the operation that the user performs on the resource.

    if let Ok(authorized) = e.enforce((sub, obj, act)) {
        if authorized {
            println!("pass")
        } else {
            println!("deny")
        }
    } else {
        println!("error occurs")
    }
    Ok(())
}

#[tokio::test]
async fn test_enforce() -> Result<()> {
    use casbin::MgmtApi;
    tracing_subscriber::fmt::init();
    
    let url = include_str!("../.env").trim_start_matches("DATABASE_URL=");

    let rb = RBatis::new();
    rb.init(MysqlDriver {}, url).unwrap();
    
    let adapter = RbatisAdapter::new(&rb).await?;
    // need to call db_sync() to create tables in database
    // adapter.db_sync().await?;

    let mut e = Enforcer::new("examples/rbac_model.conf", adapter).await?;

    // [["p", "p", "admin", "data1", "read"], ["p", "p", "admin", "data1", "write"], ["p", "p", "user", "data1", "read"]]
    println!("all policys: {:?}",e.get_all_policy());
    // all roles ["admin", "user"]
    println!("all roles: {:?}",e.get_all_subjects());
    // all paths ["data1"]
    println!("all paths: {:?}",e.get_all_objects());
    // roles have user ["admin"]
    println!("roles have user: {:?}",e.get_all_roles());

    //  [["admin", "data1", "read"], ["admin", "data1", "write"]]
    let permissions = e.get_permissions_for_user("admin", None);
    println!("admin permissions: {:?}",permissions); 

    let roles = e.get_roles_for_user("alice", None);
    println!("alice roles: {:?}", roles); // ["admin"]

    let sub = "alice"; // the user
    let obj = "data1"; // the resource
    let act = "read"; // the operation that the user performs on the resource.

    if let Ok(authorized) = e.enforce((sub, obj, act)) {
        if authorized {
            println!("pass")
        } else {
            println!("deny")
        }
    } else {
        println!("error occurs")
    }
    Ok(())
}
