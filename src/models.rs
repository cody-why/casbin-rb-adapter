use serde::{Deserialize, Serialize};

pub const TABLE_NAME: &str = "casbin_rule";


#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CasbinRule {
    pub id: Option<i32>,
    pub ptype: Option<String>,
    pub v0: Option<String>,
    pub v1: Option<String>,
    pub v2: Option<String>,
    pub v3: Option<String>,
    pub v4: Option<String>,
    pub v5: Option<String>,
}

rbatis::impl_select!(CasbinRule {}, TABLE_NAME);
rbatis::impl_insert!(CasbinRule {}, TABLE_NAME);
rbatis::impl_delete!(CasbinRule {delete_all()=>" "}, TABLE_NAME);
rbatis::impl_delete!(CasbinRule {delete_policy(ptype: &str, rules: &[String]) => 
    "`where ptype = #{ptype} `
    `AND v0 = #{rules[0]} AND v1 = #{rules[1]} `
    `AND v2 = #{rules[2]} AND v3 = #{rules[3]} ` 
    `AND v4 = #{rules[4]} AND v5 = #{rules[5]} `"}, TABLE_NAME);

rbatis::impl_delete!(CasbinRule {delete_filtered_policy_5(ptype: &str, rules: &[Option<String>]) => 
    "`where ptype = #{ptype} `
    `AND (v5 is NULL OR v5 = COALESCE(#{rules[0]},v5)) `"}, TABLE_NAME);

rbatis::impl_delete!(CasbinRule {delete_filtered_policy_4(ptype: &str, rules: &[Option<String>]) => 
    "`where ptype = #{ptype} `
    `AND (v4 is NULL OR v4 = COALESCE(#{rules[0]},v4)) ` 
    `AND (v5 is NULL OR v5 = COALESCE(#{rules[1]},v5)) `"}, TABLE_NAME);

rbatis::impl_delete!(CasbinRule {delete_filtered_policy_3(ptype: &str, rules: &[Option<String>]) => 
    "`where ptype = #{ptype} `
    `AND (v3 is NULL OR v3 = COALESCE(#{rules[0]},v3)) `
    `AND (v4 is NULL OR v4 = COALESCE(#{rules[1]},v4)) `
    `AND (v5 is NULL OR v5 = COALESCE(#{rules[2]},v5)) `"}, TABLE_NAME);

rbatis::impl_delete!(CasbinRule {delete_filtered_policy_2(ptype: &str, rules: &[Option<String>]) => 
    "`where ptype = #{ptype} `
    `AND (v2 is NULL OR v2 = COALESCE(#{rules[0]},v2)) `
    `AND (v3 is NULL OR v3 = COALESCE(#{rules[1]},v3)) `
    `AND (v4 is NULL OR v4 = COALESCE(#{rules[2]},v4)) `
    `AND (v5 is NULL OR v5 = COALESCE(#{rules[3]},v5)) `"}, TABLE_NAME);

rbatis::impl_delete!(CasbinRule {delete_filtered_policy_1(ptype: &str, rules: &[Option<String>]) => 
    "`where ptype = #{ptype} `
    `AND (v1 is NULL OR v1 = COALESCE(#{rules[0]},v1)) `
    `AND (v2 is NULL OR v2 = COALESCE(#{rules[1]},v2)) `
    `AND (v3 is NULL OR v3 = COALESCE(#{rules[2]},v3)) `
    `AND (v4 is NULL OR v4 = COALESCE(#{rules[3]},v4)) `
    `AND (v5 is NULL OR v5 = COALESCE(#{rules[4]},v5)) `"}, TABLE_NAME);

rbatis::impl_delete!(CasbinRule {delete_filtered_policy_0(ptype: &str, rules: &[Option<String>]) => 
    "`where ptype = #{ptype} `
    `AND (v0 is NULL OR v0 = COALESCE(#{rules[0]},v0)) `
    `AND (v1 is NULL OR v1 = COALESCE(#{rules[1]},v1)) `
    `AND (v2 is NULL OR v2 = COALESCE(#{rules[2]},v2)) `
    `AND (v3 is NULL OR v3 = COALESCE(#{rules[3]},v3)) `
    `AND (v4 is NULL OR v4 = COALESCE(#{rules[4]},v4)) `
    `AND (v5 is NULL OR v5 = COALESCE(#{rules[5]},v5)) `"}, TABLE_NAME);

    // "SELECT * from  casbin_rule WHERE (
    //     ptype LIKE 'g%' AND v0 LIKE ? AND v1 LIKE ? AND v2 LIKE ? AND v3 LIKE ? AND v4 LIKE ? AND v5 LIKE ? )
    // OR (
    //     ptype LIKE 'p%' AND v0 LIKE ? AND v1 LIKE ? AND v2 LIKE ? AND v3 LIKE ? AND v4 LIKE ? AND v5 LIKE ? );"
rbatis::impl_select!(CasbinRule {select_filtered_policy(g_values: Vec<&str>, p_values: Vec<&str>) => 
    "`where (ptype ='g' `
    for k,val in g_values:
        if val != '':
            `and v${k} = #{val} `
    `) or (ptype = 'p' `
    for k,val in p_values:
        if val != '':
            `and v${k} = #{val} `
    `)`"}, TABLE_NAME);

