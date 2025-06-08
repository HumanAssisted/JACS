//! # JACS Library Public Interface
//! 
//! This module documents all public functions available in the JACS library.
//! Use this as a reference for what the library can do.


/**
 
 FUNDAMENTAL FUNCTIONS

 init agent (with config for where, key management config)
 register agent (register keys, register json doc)
 validate agent (local)
 validate agent (remote) (get pki)
  

create document
register document
validate document local
validate document remote

encrypt document
decrypt document with consent from owner

 
 # AUTH FUNCTIONS

full encryption wrapper or just 
issue decryption key 

 wrap 

 unwrap 
 


 # ABSTRACTED
 

Agreements
Tasks 
Agent capabilities (MCP/ACP/A2A)










 */




// Re-export the main types users need
pub use crate::agent::Agent;
pub use crate::config::Config;
pub use crate::observability::ObservabilityConfig;

/// # Agent Management
/// Functions for creating and managing JACS agents
pub mod agent_ops {
    pub use crate::{
        get_empty_agent,
        load_agent,
        create_minimal_blank_agent,
    };
}

/// # Document Operations  
/// Functions for creating, loading, and managing documents
pub mod document_ops {
    pub use crate::shared::{
        document_create,
        document_load_and_save,
        save_document,
    };
}

/// # Agreement Operations
/// Functions for creating and managing multi-party agreements
pub mod agreement_ops {
    pub use crate::shared::{
        document_add_agreement,
        document_sign_agreement, 
        document_check_agreement,
    };
}

/// # Task Operations
/// Functions for creating and managing tasks
pub mod task_ops {
    pub use crate::{
        create_task,
        update_task,
    };
}

/// # Observability
/// Functions for logging and metrics
pub mod observability_ops {
    pub use crate::{
        init_default_observability,
        init_custom_observability,
    };
}

/// # Schema Operations
/// Functions for creating minimal JSON structures
pub mod schema_ops {
    pub use crate::schema::{
        agent_crud::create_minimal_agent,
        service_crud::create_minimal_service,
        task_crud::create_minimal_task,
        action_crud::create_minimal_action,
    };
}