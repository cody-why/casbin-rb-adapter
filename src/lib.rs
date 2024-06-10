//! examples:
//! ```rust no run
//! let rb = RBatis::new();
//! rb.init(MysqlDriver {}, url).unwrap();
//! let adapter = RbatisAdapter::new(&rb).await?;
//! // need to call db_sync() to create tables in database
//! // adapter.db_sync().await?;
//! let mut e = Enforcer::new("examples/rbac_model.conf", adapter).await?;
//! // e.enforce((sub, obj, act)).await?;
//! ```
//! 
mod actions;
mod models;
mod adapter;
mod utils;
pub use adapter::RbatisAdapter;
pub use casbin;

/// create a vec of string from arguments
/// ```rust no run
/// let args = to_vec!["arg1", "arg2"];
/// ```
#[macro_export]
macro_rules! to_vec {
    ($($x:expr),*) => {{
        vec![$($x.to_string()),*]
    }};
}

