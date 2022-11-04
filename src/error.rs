use cosmwasm_std::StdError;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum ContractError {
    #[error("{0}")]
    Std(#[from] StdError),

    #[error("Custom Error val: {val:?}")]
    CustomError { val: String },

    #[error("Unauthorized")]
    Unauthorized {},

    #[error("Too many poll options (max: 10)")]
    TooManyOptions {},

    #[error("Poll not found")]
    PollNotFound {},

    #[error("Option not found for poll #{poll_id:?}")]
    PollOptionNotFound { poll_id: String },
}
