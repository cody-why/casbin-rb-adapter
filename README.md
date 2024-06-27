[![Crates.io](https://img.shields.io/crates/v/casbin-rb-adapter.svg)](https://crates.io/crates/casbin-rb-adapter)
[![Docs](https://docs.rs/casbin-rb-adapter/badge.svg)](https://docs.rs/crate/casbin-rb-adapter/)
[![Download](https://img.shields.io/crates/d/casbin-rb-adapter.svg?style=flat-square)](https://crates.io/crates/casbin-rb-adapter)

# Casbin Rbatis adapter

Rbatis adapter for casbin. With this library, Casbin can load policy or save policy from Rbatis supported databases.

## Supported databases, see [Rbatis](https://docs.rs/crate/rbatis)
- MySQL
- PostgreSQL
- SQLite
- MSSQL
- ...

## Casbin online editor
- https://casbin.org/zh/editor

## Get started

Add the following to `Cargo.toml`:
```toml
[dependencies]
casbin-rb-adapter = "0.1"
# casbin or use casbin_rb_adapter::casbin
casbin = "2"

# rbatis integration
rbs = "4"
rbatis = "4"

# choose rbatis driver
# rbdc-mysql = "*"
# rbdc-pg = "*"
# rbdc-sqlite= "*"
# rbdc-mssql = "*"

```
```rust
// or use your project Rbatis static instance
let rb = RBatis::new();
rb.init(MysqlDriver {}, url).unwrap();

let adapter = RbatisAdapter::new(&rb).await?;
// need to call db_sync() to create tables in database
// adapter.db_sync().await?;

let mut e = Enforcer::new("examples/rbac_model.conf", adapter).await?;

// e.enforce((sub, obj, act)).await?;
```

features: 
- `tracing` logger for Adapter, 
- `runtime-tokio` runtime for casbin.
- `runtime-async-std` runtime for casbin.

## Example
[examples/mysql_sample.rs]("https://github.com/cody-why/casbin_rb_adapter/tree/main/examples")

How to run examples: 

You need to create a .env file in the project root directory, and add the following configuration:

```
DATABASE_URL=mysql://root:123456@localhost:3306/casbin
```

# update log
- v0.1.9: add `runtime-tokio` and `runtime-async-std` features for casbin, add `tracing` feature logger for Adapter. default feature `runtime-tokio`.