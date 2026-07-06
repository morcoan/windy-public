#![allow(dead_code)] // Type manager seam; actively used in Phase 4+

use std::collections::HashMap;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DataType {
    Void,
    Int(u8),
    Ptr(Box<DataType>),
    Func,
    Struct(String),
    Unknown,
}

#[derive(Default)]
pub struct DataTypeManager {
    named: HashMap<String, DataType>,
}

impl DataTypeManager {
    pub fn add(&mut self, name: impl Into<String>, ty: DataType) {
        self.named.insert(name.into(), ty);
    }

    pub fn get(&self, name: &str) -> Option<&DataType> {
        self.named.get(name)
    }
}
