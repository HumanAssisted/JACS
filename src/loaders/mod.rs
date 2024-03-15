/// these are abstract traits that must be implemented by importing libraries
///

pub trait FileLoader {
    fn load_json_by_path(&self, filepath: &String) -> String;
    fn load_agent(&self, agentid: &String) -> String;
}