use crate::actions as adapter;
use crate::models::*;
use crate::utils::*;
use async_trait::async_trait;
use casbin::{Adapter, Filter, Model, Result};
use rbatis::RBatis;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};
#[cfg(feature = "tracing")]
#[allow(unused_imports)]
use tracing::instrument;

#[allow(unused)]
macro_rules! debug {
    ($($arg:tt)+) => {{
        // tracing::debug!($($arg)+)
    }};
}
/// It is a casbin adapter use rbatis to access database.
#[derive(Clone)]
pub struct RbatisAdapter {
    pool: rbatis::RBatis,
    is_filtered: Arc<AtomicBool>,
}

impl<'a> RbatisAdapter {
    /// Creates a new CasbinRbatisAdapter instance.
    pub async fn new(rb: &RBatis) -> Result<Self> {
        let this = Self {
            pool: rb.clone(),
            is_filtered: Arc::new(AtomicBool::new(false)),
        };
        Ok(this)
    }

    /// Synchronize the database schema. It will create the table if not exist.
    pub async fn db_sync(&self) -> Result<()> {
        adapter::db_sync(&self.pool).await
    }
}

#[async_trait]
impl Adapter for RbatisAdapter {
    #[cfg_attr(feature = "tracing", instrument(skip(self, m), err))]
    async fn load_policy(&mut self, m: &mut dyn Model) -> Result<()> {
        let rules = adapter::load_policy(&self.pool).await?;

        for casbin_rule in &rules {
            if casbin_rule.ptype.is_none() {
                continue;
            }
            let ptype = casbin_rule.ptype.as_ref().unwrap();
            if let Some(ref sec) = ptype.chars().next().map(|x| x.to_string()) {
                if let Some(rule) = normalize_policy(casbin_rule) {
                    if let Some(t1) = m.get_mut_model().get_mut(sec) {
                        if let Some(t2) = t1.get_mut(ptype) {
                            t2.get_mut_policy().insert(rule);
                        }
                    }
                }
            }
        }

        Ok(())
    }

    #[cfg_attr(feature = "tracing", instrument(skip(self, m, f), fields(?p = f.p, ?g= f.g), err))]
    async fn load_filtered_policy<'a>(&mut self, m: &mut dyn Model, f: Filter<'a>) -> Result<()> {
        let rules = adapter::load_filtered_policy(&self.pool, f).await?;
        self.is_filtered.store(true, Ordering::SeqCst);

        for casbin_rule in &rules {
            if casbin_rule.ptype.is_none() {
                continue;
            }
            let ptype = casbin_rule.ptype.as_ref().unwrap();
            if let Some(ref sec) = ptype.chars().next().map(|x| x.to_string()) {
                if let Some(policy) = normalize_policy(casbin_rule) {
                    if let Some(t1) = m.get_mut_model().get_mut(sec) {
                        if let Some(t2) = t1.get_mut(ptype) {
                            t2.get_mut_policy().insert(policy);
                        }
                    }
                }
            }
        }

        Ok(())
    }

    #[cfg_attr(feature = "tracing", instrument(skip(self, m), err))]
    async fn save_policy(&mut self, m: &mut dyn Model) -> Result<()> {
        let mut rules = vec![];

        if let Some(ast_map) = m.get_model().get("p") {
            for (ptype, ast) in ast_map {
                let new_rules = ast.get_policy().into_iter().filter_map(|x| save_policy_line(ptype, x));

                rules.extend(new_rules);
            }
        }

        if let Some(ast_map) = m.get_model().get("g") {
            for (ptype, ast) in ast_map {
                let new_rules = ast.get_policy().into_iter().filter_map(|x| save_policy_line(ptype, x));

                rules.extend(new_rules);
            }
        }
        adapter::save_policy(&self.pool, rules).await
    }

    #[cfg_attr(feature = "tracing", instrument(skip(self), err, ret))]
    async fn add_policy(&mut self, _sec: &str, ptype: &str, rule: Vec<String>) -> Result<bool> {
        if let Some(new_rule) = save_policy_line(ptype, rule.as_slice()) {
            let result = adapter::add_policy(&self.pool, new_rule).await;
            return result;
        }

        Ok(false)
    }

    #[cfg_attr(feature = "tracing", instrument(skip(self), err, ret))]
    async fn add_policies(&mut self, _sec: &str, ptype: &str, rules: Vec<Vec<String>>) -> Result<bool> {
        let new_rules = rules
            .iter()
            .filter_map(|x| save_policy_line(ptype, x))
            .collect::<Vec<CasbinRule>>();

        adapter::add_policies(&self.pool, new_rules).await
    }

    #[cfg_attr(feature = "tracing", instrument(skip(self), err, ret))]
    async fn remove_policy(&mut self, _sec: &str, pt: &str, rule: Vec<String>) -> Result<bool> {
        adapter::remove_policy(&self.pool, pt, rule).await
    }

    #[cfg_attr(feature = "tracing", instrument(skip(self), err, ret))]
    async fn remove_policies(&mut self, _sec: &str, pt: &str, rules: Vec<Vec<String>>) -> Result<bool> {
        adapter::remove_policies(&self.pool, pt, rules).await
    }
    #[cfg_attr(feature = "tracing", instrument(skip(self), err, ret))]
    async fn remove_filtered_policy(
        &mut self,
        _sec: &str,
        pt: &str,
        field_index: usize,
        field_values: Vec<String>,
    ) -> Result<bool> {
        if field_index <= 5 && !field_values.is_empty() && field_values.len() + field_index <= 6 {
            adapter::remove_filtered_policy(&self.pool, pt, field_index, field_values).await
        } else {
            Ok(false)
        }
    }

    #[cfg_attr(feature = "tracing", instrument(skip(self), err))]
    async fn clear_policy(&mut self) -> Result<()> {
        adapter::clear_policy(&self.pool).await
    }

    #[cfg_attr(feature = "tracing", instrument(skip(self)))]
    fn is_filtered(&self) -> bool {
        self.is_filtered.load(Ordering::SeqCst)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::to_vec;
    use rbdc_mysql::driver::MysqlDriver;

    #[tokio::test]
    async fn test_adapter() {
        use casbin::prelude::*;
        tracing_subscriber::fmt::init();
        let file_adapter = FileAdapter::new("examples/rbac_policy.csv");
        let m = DefaultModel::from_file("examples/rbac_model.conf").await.unwrap();
        let mut e = Enforcer::new(m, file_adapter).await.unwrap();

        let url = include_str!("../.env").trim_start_matches("DATABASE_URL=");

        let rb = RBatis::new();
        rb.init(MysqlDriver {}, url).unwrap();
        let mut adapter = RbatisAdapter::new(&rb).await.unwrap();
        adapter.db_sync().await.unwrap();

        adapter.clear_policy().await.unwrap();
        assert!(adapter.save_policy(e.get_mut_model()).await.is_ok());

        assert!(adapter
            .remove_policy("", "p", to_vec!["alice", "data1", "read"])
            .await
            .unwrap());
        assert!(adapter.remove_policy("", "p", to_vec!["bob", "data2", "write"]).await.is_ok());
        assert!(adapter
            .remove_policy("", "p", to_vec!["data2_admin", "data2", "read"])
            .await
            .is_ok());
        assert!(adapter
            .remove_policy("", "p", to_vec!["data2_admin", "data2", "write"])
            .await
            .is_ok());
        assert!(adapter.remove_policy("", "g", to_vec!["alice", "data2_admin"]).await.is_ok());

        assert!(adapter.add_policy("", "p", to_vec!["alice", "data1", "read"]).await.is_ok());
        assert!(adapter.add_policy("", "p", to_vec!["bob", "data2", "write"]).await.is_ok());
        assert!(adapter
            .add_policy("", "p", to_vec!["data2_admin", "data2", "read"])
            .await
            .is_ok());
        assert!(adapter
            .add_policy("", "p", to_vec!["data2_admin", "data2", "write"])
            .await
            .is_ok());

        assert!(adapter
            .remove_policies(
                "",
                "p",
                vec![
                    to_vec!["alice", "data1", "read"],
                    to_vec!["bob", "data2", "write"],
                    to_vec!["data2_admin", "data2", "read"],
                    to_vec!["data2_admin", "data2", "write"],
                ]
            )
            .await
            .is_ok());

        assert!(adapter
            .add_policies(
                "",
                "p",
                vec![
                    to_vec!["alice", "data1", "read"],
                    to_vec!["bob", "data2", "write"],
                    to_vec!["data2_admin", "data2", "read"],
                    to_vec!["data2_admin", "data2", "write"],
                ]
            )
            .await
            .is_ok());

        assert!(adapter.add_policy("", "g", to_vec!["alice", "data2_admin"]).await.is_ok());

        assert!(adapter
            .remove_policy("", "p", to_vec!["alice", "data1", "read"])
            .await
            .is_ok());
        assert!(adapter.remove_policy("", "p", to_vec!["bob", "data2", "write"]).await.is_ok());
        assert!(adapter
            .remove_policy("", "p", to_vec!["data2_admin", "data2", "read"])
            .await
            .is_ok());
        assert!(adapter
            .remove_policy("", "p", to_vec!["data2_admin", "data2", "write"])
            .await
            .is_ok());
        assert!(adapter.remove_policy("", "g", to_vec!["alice", "data2_admin"]).await.is_ok());

        assert!(!adapter
            .remove_policy("", "g", to_vec!["alice", "data2_admin", "not_exists"])
            .await
            .unwrap());

        assert!(adapter.add_policy("", "g", to_vec!["alice", "data2_admin"]).await.is_ok());
        assert!(adapter.add_policy("", "g", to_vec!["alice", "data2_admin"]).await.is_err());

        assert!(!adapter
            .remove_filtered_policy("", "g", 0, to_vec!["alice", "data2_admin", "not_exists"],)
            .await
            .unwrap());

        assert!(adapter
            .remove_filtered_policy("", "g", 0, to_vec!["alice", "data2_admin"])
            .await
            .unwrap());

        assert!(adapter
            .add_policy("", "g", to_vec!["alice", "data2_admin", "domain1", "domain2"],)
            .await
            .is_ok());
        assert!(adapter
            .remove_filtered_policy("", "g", 1, to_vec!["data2_admin", "domain1", "domain2"],)
            .await
            .unwrap());

        // GitHub issue: https://github.com/casbin-rs/sqlx-adapter/issues/64
        assert!(adapter.add_policy("", "g", to_vec!["carol", "data1_admin"],).await.is_ok());
        assert!(adapter.remove_filtered_policy("", "g", 0, to_vec!["carol"],).await.unwrap());
        assert_eq!(vec![] as Vec<String>, e.get_roles_for_user("carol", None));

        // GitHub issue: https://github.com/casbin-rs/sqlx-adapter/pull/90
        // add policies:
        // p, alice_rfp, book_rfp, read_rfp
        // p, bob_rfp, book_rfp, read_rfp
        // p, bob_rfp, book_rfp, write_rfp
        // p, alice_rfp, pen_rfp, get_rfp
        // p, bob_rfp, pen_rfp, get_rfp
        // p, alice_rfp, pencil_rfp, get_rfp
        assert!(adapter
            .add_policy("", "p", to_vec!["alice_rfp", "book_rfp", "read_rfp"],)
            .await
            .is_ok());
        assert!(adapter
            .add_policy("", "p", to_vec!["bob_rfp", "book_rfp", "read_rfp"],)
            .await
            .is_ok());
        assert!(adapter
            .add_policy("", "p", to_vec!["bob_rfp", "book_rfp", "write_rfp"],)
            .await
            .is_ok());
        assert!(adapter
            .add_policy("", "p", to_vec!["alice_rfp", "pen_rfp", "get_rfp"],)
            .await
            .is_ok());
        assert!(adapter
            .add_policy("", "p", to_vec!["bob_rfp", "pen_rfp", "get_rfp"],)
            .await
            .is_ok());
        assert!(adapter
            .add_policy("", "p", to_vec!["alice_rfp", "pencil_rfp", "get_rfp"],)
            .await
            .is_ok());

        // should remove (return true) all policies where "book_rfp" is in the second position
        assert!(adapter
            .remove_filtered_policy("", "p", 1, to_vec!["book_rfp"],)
            .await
            .unwrap());

        // should remove (return true) all policies which match "alice_rfp" on first position
        // and "get_rfp" on third position
        assert!(adapter
            .remove_filtered_policy("", "p", 0, to_vec!["alice_rfp", "", "get_rfp"],)
            .await
            .unwrap());

        // shadow the previous enforcer
        let mut e = Enforcer::new("examples/rbac_with_domains_model.conf", "examples/rbac_with_domains_policy.csv")
            .await
            .unwrap();

        adapter.clear_policy().await.unwrap();
        assert!(adapter.save_policy(e.get_mut_model()).await.is_ok());
        e.set_adapter(adapter).await.unwrap();

        let filter = Filter {
            p: vec!["", "domain1"],
            g: vec!["", "", "domain1"],
        };

        e.load_filtered_policy(filter).await.unwrap();
        assert!(e.enforce(("alice", "domain1", "data1", "read")).unwrap());
        assert!(e.enforce(("alice", "domain1", "data1", "write")).unwrap());
        assert!(!e.enforce(("alice", "domain1", "data2", "read")).unwrap());
        assert!(!e.enforce(("alice", "domain1", "data2", "write")).unwrap());
        assert!(!e.enforce(("bob", "domain2", "data2", "read")).unwrap());
        assert!(!e.enforce(("bob", "domain2", "data2", "write")).unwrap());
    }
}
