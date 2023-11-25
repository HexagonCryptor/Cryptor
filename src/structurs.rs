use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Clone)]
pub struct FileStruct {
    pub(crate) format: String,
    pub(crate) file: Vec::<u8>
}