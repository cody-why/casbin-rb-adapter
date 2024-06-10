use casbin::{
    error::{AdapterError, Error as CasbinError, ModelError},
    Filter, Result,
};
use rbatis::RBatis;

use crate::models::CasbinRule;

pub async fn db_sync(rb: &rbatis::RBatis) -> Result<()> {
    let driver_type = rb.driver_type().unwrap();

    let sql = match driver_type {
        "mysql" => include_str!("../sql/mysql.sql"),
        "postgres" => include_str!("../sql/postgres.sql"),
        "sqlite" => include_str!("../sql/sqlite.sql"),
        "mssql" => include_str!("../sql/mssql.sql"),
        _ => {
            let err_msg = format!("unsupported driver type: {}, please create table casbin_rule manually. ", driver_type);
            let err = CasbinError::from(ModelError::Other(err_msg));
            return Err(err);
        },
    };

    rb.exec(sql, vec![])
        .await
        .map(|_| {})
        .map_err(|err| CasbinError::from(AdapterError(Box::new(err))))
}
 

pub(crate) async fn clear_policy(rb: &RBatis) -> Result<()> {
    CasbinRule::delete_all(rb)
        .await
        .map_err(|err| CasbinError::from(AdapterError(Box::new(err))))?;
    Result::Ok(())
}

pub(crate) async fn save_policy(rb: &RBatis, rules: Vec<CasbinRule>) -> Result<()> {
    let mut tx = rb
        .acquire_begin()
        .await
        .map_err(|err| CasbinError::from(AdapterError(Box::new(err))))?;
    // CasbinRule::delete_all(&tx).await.map_err(|err| CasbinError::from(AdapterError(Box::new(err))))?;
    for rule in rules {
        CasbinRule::insert(&tx, &rule)
            .await
            .map_err(|err| CasbinError::from(AdapterError(Box::new(err))))?;
    }
    tx.commit()
        .await
        .map_err(|err| CasbinError::from(AdapterError(Box::new(err))))?;
    Ok(())
}

pub async fn remove_policy(rb: &RBatis, pt: &str, rule: Vec<String>) -> Result<bool> {
    remove_policies(rb, pt, vec![rule]).await
}

pub async fn remove_policies(rb: &RBatis, pt: &str, rules: Vec<Vec<String>>) -> Result<bool> {
    let mut tx = rb
        .acquire_begin()
        .await
        .map_err(|err| CasbinError::from(AdapterError(Box::new(err))))?;
    let mut sum = 0;
    for rule in rules {
        let rule = normalize_casbin_rule(rule);
        let r = CasbinRule::delete_policy(&tx, pt, &rule)
            .await
            .map_err(|err| CasbinError::from(AdapterError(Box::new(err))))?;
        sum += r.rows_affected;
    }
    tx.commit()
        .await
        .map_err(|err| CasbinError::from(AdapterError(Box::new(err))))?;
    Ok(sum > 0)
}

pub async fn remove_filtered_policy(
    rb: &RBatis,
    pt: &str,
    field_index: usize,
    field_values: Vec<String>,
) -> Result<bool> {
    let field_values = normalize_casbin_rule_option(field_values);

    let result = match field_index {
        1 => CasbinRule::delete_filtered_policy_1(rb, pt, &field_values).await,
        2 => CasbinRule::delete_filtered_policy_2(rb, pt, &field_values).await,
        3 => CasbinRule::delete_filtered_policy_3(rb, pt, &field_values).await,
        4 => CasbinRule::delete_filtered_policy_4(rb, pt, &field_values).await,
        5 => CasbinRule::delete_filtered_policy_5(rb, pt, &field_values).await,
        _ => CasbinRule::delete_filtered_policy_0(rb, pt, &field_values).await,
    };
    let result = result.map_err(|err| CasbinError::from(AdapterError(Box::new(err))))?;
    Ok(result.rows_affected > 0)
}

pub(crate) async fn load_policy(rb: &RBatis) -> Result<Vec<CasbinRule>> {
    let vec_rules = CasbinRule::select_all(rb)
        .await
        .map_err(|err| CasbinError::from(AdapterError(Box::new(err))))?;
    Result::Ok(vec_rules)
}

pub(crate) async fn load_filtered_policy<'a>(rb: &RBatis, f: Filter<'a>) -> Result<Vec<CasbinRule>> {
    let vec_rules = CasbinRule::select_filtered_policy(rb, f.g, f.p)
        .await
        .map_err(|err| CasbinError::from(AdapterError(Box::new(err))))?;
    // println!("vec_rules: {vec_rules:?}");
    Result::Ok(vec_rules)
}

pub(crate) async fn add_policy(rb: &RBatis, new_rule: CasbinRule) -> Result<bool> {
    CasbinRule::insert(rb, &new_rule)
        .await
        .map_err(|err| CasbinError::from(AdapterError(Box::new(err))))?;
    Result::Ok(true)
}

pub(crate) async fn add_policies(rb: &RBatis, rules: Vec<CasbinRule>) -> Result<bool> {
    let mut tx = rb
        .acquire_begin()
        .await
        .map_err(|err| CasbinError::from(AdapterError(Box::new(err))))?;

    for rule in rules {
        CasbinRule::insert(&tx, &rule)
            .await
            .map_err(|err| CasbinError::from(AdapterError(Box::new(err))))?;
    }
    tx.commit()
        .await
        .map(|_| true)
        .map_err(|err| CasbinError::from(AdapterError(Box::new(err))))
}

// resize the vec to 6 fields. fill it with empty string.
fn normalize_casbin_rule(mut rule: Vec<String>) -> Vec<String> {
    rule.resize(6, String::new());
    rule
}

// if the field value is empty, set it to None, otherwise set it to Some(value),
// and resize the vec to 6 fields.
fn normalize_casbin_rule_option(rule: Vec<String>) -> Vec<Option<String>> {
    let mut rule_with_option = rule
        .iter()
        .map(|x| match x.is_empty() {
            true => None,
            false => Some(x.clone()),
        })
        .collect::<Vec<Option<String>>>();
    rule_with_option.resize(6, None);
    rule_with_option
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::to_vec;

    #[test]
    fn test_normalize_casbin_rule() {
        let rule = to_vec!["alice", "data1", "write"];
        let new_rule = normalize_casbin_rule(rule.clone());
        println!("{new_rule:?}");
        assert!(new_rule.len() == 6);
        assert_eq!(new_rule[0], "alice".to_string());
        assert_eq!(new_rule[1], "data1".to_string());
        assert_eq!(new_rule[2], "write".to_string());
        assert_eq!(new_rule[3], "".to_string());
        assert_eq!(new_rule[4], "".to_string());
        assert_eq!(new_rule[5], "".to_string());

        let new_rule = normalize_casbin_rule_option(rule);
        println!("{new_rule:?}");
        assert!(new_rule.len() == 6);
        assert_eq!(new_rule[0], Some("alice".to_string()));
        assert_eq!(new_rule[1], Some("data1".to_string()));
        assert_eq!(new_rule[2], Some("write".to_string()));
        assert_eq!(new_rule[3], None);
        assert_eq!(new_rule[4], None);
        assert_eq!(new_rule[5], None);
    }
}
