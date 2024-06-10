#![allow(clippy::get_first)]
use crate::models::CasbinRule;

// converts the policy vec (6 elements) to a CasbinRule struct.
pub(crate) fn save_policy_line(ptype: &str, rule: &[String]) -> Option<CasbinRule> {
    if ptype.trim().is_empty() || rule.is_empty() {
        return None;
    }
    Some(CasbinRule {
        id: None,
        ptype: Some(ptype.to_owned()),
        v0: rule.get(0).cloned().or(Some("".to_owned())),
        v1: rule.get(1).cloned().or(Some("".to_owned())),
        v2: rule.get(2).cloned().or(Some("".to_owned())),
        v3: rule.get(3).cloned().or(Some("".to_owned())),
        v4: rule.get(4).cloned().or(Some("".to_owned())),
        v5: rule.get(5).cloned().or(Some("".to_owned())),
    })
}

// converts the CasbinRule struct to a policy vec (if it has any values).
pub(crate) fn normalize_policy(casbin_rule: &CasbinRule) -> Option<Vec<String>> {
    let mut result = vec![];

    if let Some(v) = &casbin_rule.v0 {
        if !v.is_empty(){
            result.push(v.to_owned());
        }
    };
    if let Some(v) = &casbin_rule.v1 {
        if !v.is_empty(){
            result.push(v.to_owned());
        }
    };
    if let Some(v) = &casbin_rule.v2 {
        if !v.is_empty(){
            result.push(v.to_owned());
        }
    };
    if let Some(v) = &casbin_rule.v3 {
        if !v.is_empty(){
            result.push(v.to_owned());
        }
    };
    if let Some(v) = &casbin_rule.v4 {
        if !v.is_empty(){
            result.push(v.to_owned());
        }
    };
    if let Some(v) = &casbin_rule.v5 {
        if !v.is_empty(){
            result.push(v.to_owned());
        }
    };
    if result.is_empty() {
        return None;
    }
    Some(result)
    
}


#[cfg(test)]
mod tests {
    use super::*;
    use crate::to_vec;

    #[test]
    fn test_save_policy_line() {
        let rule = to_vec!["alice", "data1", "read"];
        let casbin_rule = save_policy_line("p", &rule).unwrap();
        assert_eq!(casbin_rule.ptype, Some("p".to_owned()));
        assert_eq!(casbin_rule.v0, Some("alice".to_owned()));
        assert_eq!(casbin_rule.v1, Some("data1".to_owned()));
        assert_eq!(casbin_rule.v2, Some("read".to_owned()));
        assert_eq!(casbin_rule.v3, Some("".to_owned()));
        assert_eq!(casbin_rule.v4, Some("".to_owned()));
        assert_eq!(casbin_rule.v5, Some("".to_owned()));
    }

    #[test]
    fn test_normalize_policy() {
        let casbin_rule = CasbinRule {
            id: None,
            ptype: Some("p".to_owned()),
            v0: Some("alice".to_owned()),
            v1: Some("data1".to_owned()),
            v2: Some("read".to_owned()),
            v3: None,
            v4: None,
            v5: Some("".to_owned()),
        };
        let policy = normalize_policy(&casbin_rule).unwrap();
        assert_eq!(policy, to_vec!["alice", "data1", "read"]);
        
    }

}