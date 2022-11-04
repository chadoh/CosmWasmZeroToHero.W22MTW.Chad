#[cfg(not(feature = "library"))]
use cosmwasm_std::entry_point;
use cosmwasm_std::{
    to_binary, Binary, Deps, DepsMut, Env, MessageInfo, Order, Response, StdResult,
};

use cw2::set_contract_version;

use crate::error::ContractError;
use crate::msg::{
    AllPollsResponse, ConfigResponse, ExecuteMsg, InstantiateMsg, PollResponse, QueryMsg,
    VoteResponse,
};
use crate::state::{Ballot, Config, Poll, BALLOTS, CONFIG, POLLS};

const CONTRACT_NAME: &str = "crates.io:cw-starter";
const CONTRACT_VERSION: &str = env!("CARGO_PKG_VERSION");

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn instantiate(
    deps: DepsMut,
    _env: Env,
    info: MessageInfo,
    msg: InstantiateMsg,
) -> Result<Response, ContractError> {
    set_contract_version(deps.storage, CONTRACT_NAME, CONTRACT_VERSION)?;
    let admin = msg.admin.unwrap_or(info.sender.to_string());
    let validated_admin = deps.api.addr_validate(&admin)?;
    let config = Config {
        admin: validated_admin.clone(),
    };
    CONFIG.save(deps.storage, &config)?;
    Ok(Response::new()
        .add_attribute("action", "instantiate")
        .add_attribute("admin", validated_admin.to_string()))
}

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn execute(
    deps: DepsMut,
    env: Env,
    info: MessageInfo,
    msg: ExecuteMsg,
) -> Result<Response, ContractError> {
    match msg {
        ExecuteMsg::CreatePoll {
            poll_id,
            question,
            options,
        } => execute_create_poll(deps, env, info, poll_id, question, options),
        ExecuteMsg::Vote { poll_id, vote } => execute_vote(deps, env, info, poll_id, vote),
        _ => unimplemented!(),
        // ExecuteMsg::DeletePoll { poll_id } => unimplemented!(),
        // ExecuteMsg::RevokeVote { poll_id } => unimplemented!(),
    }
}

fn execute_vote(
    deps: DepsMut,
    _env: Env,
    info: MessageInfo,
    poll_id: String,
    vote: String,
) -> Result<Response, ContractError> {
    let poll = POLLS.may_load(deps.storage, &poll_id)?;

    if poll.is_none() {
        return Err(ContractError::PollNotFound { poll_id: poll_id });
    }

    let mut poll = poll.unwrap();

    BALLOTS.update(
        deps.storage,
        (info.sender.clone(), &poll_id),
        |ballot| -> StdResult<Ballot> {
            match ballot {
                Some(ballot) => {
                    let position_of_old_vote = poll
                        .options
                        .iter()
                        .position(|option| option.0 == ballot.option)
                        .unwrap();
                    poll.options[position_of_old_vote].1 -= 1;
                    Ok(Ballot {
                        option: vote.clone(),
                    })
                }
                None => Ok(Ballot {
                    option: vote.clone(),
                }),
            }
        },
    )?;

    let position = poll.options.iter().position(|option| option.0 == vote);
    if position.is_none() {
        return Err(ContractError::PollOptionNotFound {
            poll_id: poll_id,
            bad_option: vote,
        });
    }
    poll.options[position.unwrap()].1 += 1;
    POLLS.save(deps.storage, &poll_id, &poll)?;

    Ok(Response::new()
        .add_attribute("action", "execute_vote")
        .add_attribute("poll_id", poll_id)
        .add_attribute("option", vote)
        .add_attribute("voter", info.sender))
}

fn execute_create_poll(
    deps: DepsMut,
    _env: Env,
    info: MessageInfo,
    poll_id: String,
    question: String,
    options: Vec<String>,
) -> Result<Response, ContractError> {
    if options.len() > 10 {
        return Err(ContractError::TooManyOptions {});
    }

    let mut opts: Vec<(String, u64)> = vec![];
    for option in options {
        opts.push((option, 0));
    }

    let poll = Poll {
        creator: info.sender,
        question,
        options: opts,
    };

    POLLS.save(deps.storage, &poll_id, &poll)?;

    Ok(Response::new()
        .add_attribute("action", "execute_create_poll")
        .add_attribute("poll_id", poll_id)
        .add_attribute("number_of_options", poll.options.len().to_string())
        .add_attribute("owner", poll.creator))
}

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn query(deps: Deps, env: Env, msg: QueryMsg) -> StdResult<Binary> {
    match msg {
        QueryMsg::Config {} => query_config(deps, env),
        QueryMsg::AllPolls {} => query_all_polls(deps, env),
        QueryMsg::Poll { poll_id } => query_poll(deps, env, poll_id),
        QueryMsg::Vote { poll_id, address } => query_vote(deps, env, poll_id, address),
    }
}

fn query_config(deps: Deps, _env: Env) -> StdResult<Binary> {
    let config = CONFIG.load(deps.storage)?;
    to_binary(&ConfigResponse { config: config })
}

fn query_all_polls(deps: Deps, _env: Env) -> StdResult<Binary> {
    let polls = POLLS
        .range(deps.storage, None, None, Order::Ascending)
        .map(|p| Ok(p?.1))
        .collect::<StdResult<Vec<_>>>()?;
    to_binary(&AllPollsResponse { polls })
}

fn query_poll(deps: Deps, _env: Env, poll_id: String) -> StdResult<Binary> {
    let poll = POLLS.may_load(deps.storage, &poll_id)?;
    to_binary(&PollResponse { poll })
}

fn query_vote(deps: Deps, _env: Env, poll_id: String, address: String) -> StdResult<Binary> {
    let validated_address = deps.api.addr_validate(&address).unwrap();
    let vote = BALLOTS.may_load(deps.storage, (validated_address, &poll_id))?;

    to_binary(&VoteResponse { vote })
}

#[cfg(test)]
mod tests {
    use crate::contract::{execute, instantiate, query};
    use crate::error::ContractError;
    use crate::msg::{
        AllPollsResponse, ConfigResponse, ExecuteMsg, InstantiateMsg, PollResponse, QueryMsg,
        VoteResponse,
    };
    use cosmwasm_std::testing::{mock_dependencies, mock_env, mock_info};
    use cosmwasm_std::{attr, from_binary};

    pub const ADDR1: &str = "addr1";
    pub const ADDR2: &str = "addr2";

    #[test]
    fn test_instantiate() {
        let mut deps = mock_dependencies();
        let env = mock_env();
        let info = mock_info(ADDR1, &vec![]);

        let msg = InstantiateMsg { admin: None };
        let res = instantiate(deps.as_mut(), env, info, msg).unwrap();

        assert_eq!(
            res.attributes,
            vec![attr("action", "instantiate"), attr("admin", ADDR1)]
        )
    }

    #[test]
    fn test_instantiate_with_admin() {
        let mut deps = mock_dependencies();
        let env = mock_env();
        let info = mock_info(ADDR1, &vec![]);

        let msg = InstantiateMsg {
            admin: Some(ADDR2.to_string()),
        };
        let res = instantiate(deps.as_mut(), env, info, msg).unwrap();

        assert_eq!(
            res.attributes,
            vec![attr("action", "instantiate"), attr("admin", ADDR2)]
        )
    }

    #[test]
    fn test_execute_create_poll_valid() {
        let mut deps = mock_dependencies();
        let env = mock_env();
        let info = mock_info(ADDR1, &vec![]);
        let msg = InstantiateMsg { admin: None };
        let _res = instantiate(deps.as_mut(), env.clone(), info.clone(), msg).unwrap();

        let msg = ExecuteMsg::CreatePoll {
            poll_id: "some_id".to_string(),
            question: "What's your favourite Cosmos coin?".to_string(),
            options: vec![
                "Cosmos Hub".to_string(),
                "Juno".to_string(),
                "Osmosis".to_string(),
            ],
        };

        let res = execute(deps.as_mut(), env.clone(), info.clone(), msg).unwrap();

        assert_eq!(
            res.attributes,
            vec![
                attr("action", "execute_create_poll"),
                attr("poll_id", "some_id"),
                attr("number_of_options", "3"),
                attr("owner", ADDR1),
            ]
        )
    }

    #[test]
    fn test_execute_create_poll_invalid() {
        let mut deps = mock_dependencies();
        let env = mock_env();
        let info = mock_info(ADDR1, &vec![]);
        let msg = InstantiateMsg { admin: None };
        let _res = instantiate(deps.as_mut(), env.clone(), info.clone(), msg).unwrap();

        let msg = ExecuteMsg::CreatePoll {
            poll_id: "some_id".to_string(),
            question: "What's your favourite number?".to_string(),
            options: vec![
                "1".to_string(),
                "2".to_string(),
                "3".to_string(),
                "4".to_string(),
                "5".to_string(),
                "6".to_string(),
                "7".to_string(),
                "8".to_string(),
                "9".to_string(),
                "10".to_string(),
                "11".to_string(),
            ],
        };

        let res = execute(deps.as_mut(), env.clone(), info.clone(), msg).unwrap_err();

        assert!(matches!(res, ContractError::TooManyOptions {}))
    }

    #[test]
    fn test_execute_vote_valid() {
        let mut deps = mock_dependencies();
        let env = mock_env();
        let info = mock_info(ADDR1, &vec![]);
        let msg = InstantiateMsg { admin: None };
        let _res = instantiate(deps.as_mut(), env.clone(), info.clone(), msg).unwrap();

        let msg = ExecuteMsg::CreatePoll {
            poll_id: "some_id".to_string(),
            question: "What's your favourite Cosmos coin?".to_string(),
            options: vec![
                "Cosmos Hub".to_string(),
                "Juno".to_string(),
                "Osmosis".to_string(),
            ],
        };

        let _res = execute(deps.as_mut(), env.clone(), info.clone(), msg).unwrap();

        let msg = ExecuteMsg::Vote {
            poll_id: "some_id".to_string(),
            vote: "Juno".to_string(),
        };

        let res = execute(deps.as_mut(), env.clone(), info.clone(), msg).unwrap();

        assert_eq!(
            res.attributes,
            vec![
                attr("action", "execute_vote"),
                attr("poll_id", "some_id"),
                attr("option", "Juno"),
                attr("voter", ADDR1),
            ],
        );

        let msg = ExecuteMsg::Vote {
            poll_id: "some_id".to_string(),
            vote: "Osmosis".to_string(),
        };

        let res = execute(deps.as_mut(), env.clone(), info.clone(), msg).unwrap();

        assert_eq!(
            res.attributes,
            vec![
                attr("action", "execute_vote"),
                attr("poll_id", "some_id"),
                attr("option", "Osmosis"),
                attr("voter", ADDR1),
            ],
        )
    }

    #[test]
    fn test_execute_vote_invalid() {
        let mut deps = mock_dependencies();
        let env = mock_env();
        let info = mock_info(ADDR1, &vec![]);
        let msg = InstantiateMsg { admin: None };
        let _res = instantiate(deps.as_mut(), env.clone(), info.clone(), msg).unwrap();

        let msg = ExecuteMsg::Vote {
            poll_id: "OOPS_WRONG_ID".to_string(),
            vote: "Juno".to_string(),
        };

        let res = execute(deps.as_mut(), env.clone(), info.clone(), msg).unwrap_err();

        assert!(matches!(res, ContractError::PollNotFound { poll_id: _ }));

        let msg = ExecuteMsg::CreatePoll {
            poll_id: "some_id".to_string(),
            question: "What's your favourite Cosmos coin?".to_string(),
            options: vec!["Juno".to_string()],
        };

        let _res = execute(deps.as_mut(), env.clone(), info.clone(), msg).unwrap();

        let msg = ExecuteMsg::Vote {
            poll_id: "some_id".to_string(),
            vote: "OOPS INVALID OPTION".to_string(),
        };

        let res = execute(deps.as_mut(), env.clone(), info.clone(), msg).unwrap_err();

        assert!(matches!(
            res,
            ContractError::PollOptionNotFound {
                poll_id: _,
                bad_option: _,
            }
        ));
    }

    #[test]
    fn test_query_config() {
        let mut deps = mock_dependencies();
        let env = mock_env();
        let info = mock_info(ADDR1, &vec![]);
        // Instantiate the contract
        let msg = InstantiateMsg { admin: None };
        let _res = instantiate(deps.as_mut(), env.clone(), info.clone(), msg).unwrap();

        // query all polls when none have been created yet
        let msg = QueryMsg::Config {};
        let bin = query(deps.as_ref(), env.clone(), msg).unwrap();
        let res: ConfigResponse = from_binary(&bin).unwrap();
        assert_eq!(res.config.admin, ADDR1.to_string());
    }

    #[test]
    fn test_query_all_polls() {
        let mut deps = mock_dependencies();
        let env = mock_env();
        let info = mock_info(ADDR1, &vec![]);
        // Instantiate the contract
        let msg = InstantiateMsg { admin: None };
        let _res = instantiate(deps.as_mut(), env.clone(), info.clone(), msg).unwrap();

        // query all polls when none have been created yet
        let msg = QueryMsg::AllPolls {};
        let bin = query(deps.as_ref(), env.clone(), msg).unwrap();
        let res: AllPollsResponse = from_binary(&bin).unwrap();
        assert_eq!(res.polls.len(), 0);

        // Create a poll
        let msg = ExecuteMsg::CreatePoll {
            poll_id: "some_id_1".to_string(),
            question: "What's your favourite Cosmos coin?".to_string(),
            options: vec![
                "Cosmos Hub".to_string(),
                "Juno".to_string(),
                "Osmosis".to_string(),
            ],
        };
        let _res = execute(deps.as_mut(), env.clone(), info.clone(), msg).unwrap();

        // Create a second poll
        let msg = ExecuteMsg::CreatePoll {
            poll_id: "some_id_2".to_string(),
            question: "What's your colour?".to_string(),
            options: vec!["Red".to_string(), "Green".to_string(), "Blue".to_string()],
        };
        let _res = execute(deps.as_mut(), env.clone(), info, msg).unwrap();

        let msg = QueryMsg::AllPolls {};
        let bin = query(deps.as_ref(), env, msg).unwrap();
        let res: AllPollsResponse = from_binary(&bin).unwrap();
        assert_eq!(res.polls.len(), 2)
    }

    #[test]
    fn test_query_poll() {
        let mut deps = mock_dependencies();
        let env = mock_env();
        let info = mock_info(ADDR1, &vec![]);
        // Instantiate the contract
        let msg = InstantiateMsg { admin: None };
        let _res = instantiate(deps.as_mut(), env.clone(), info.clone(), msg).unwrap();

        // Query a poll before it's created
        let msg = QueryMsg::Poll {
            poll_id: "lol".to_string(),
        };
        let bin = query(deps.as_ref(), env.clone(), msg).unwrap();
        let res: PollResponse = from_binary(&bin).unwrap();
        assert!(res.poll.is_none());

        // Create a poll
        let msg = ExecuteMsg::CreatePoll {
            poll_id: "some_id_1".to_string(),
            question: "What's your favourite Cosmos coin?".to_string(),
            options: vec!["Juno".to_string()],
        };
        let _res = execute(deps.as_mut(), env.clone(), info.clone(), msg).unwrap();

        // Query real poll
        let msg = QueryMsg::Poll {
            poll_id: "some_id_1".to_string(),
        };
        let bin = query(deps.as_ref(), env, msg).unwrap();
        let res: PollResponse = from_binary(&bin).unwrap();
        assert!(res.poll.is_some());
    }

    #[test]
    fn test_query_vote() {
        let mut deps = mock_dependencies();
        let env = mock_env();
        let info = mock_info(ADDR1, &vec![]);
        // Instantiate the contract
        let msg = InstantiateMsg { admin: None };
        let _res = instantiate(deps.as_mut(), env.clone(), info.clone(), msg).unwrap();

        let msg = ExecuteMsg::CreatePoll {
            poll_id: "some_id".to_string(),
            question: "What's your favourite Cosmos coin?".to_string(),
            options: vec![
                "Cosmos Hub".to_string(),
                "Juno".to_string(),
                "Osmosis".to_string(),
            ],
        };

        let _res = execute(deps.as_mut(), env.clone(), info.clone(), msg).unwrap();

        let msg = ExecuteMsg::Vote {
            poll_id: "some_id".to_string(),
            vote: "Juno".to_string(),
        };

        let _res = execute(deps.as_mut(), env.clone(), info.clone(), msg).unwrap();

        let msg = QueryMsg::Vote {
            poll_id: "some_id".to_string(),
            address: ADDR1.to_string(),
        };
        let bin = query(deps.as_ref(), env.clone(), msg).unwrap();
        let res: VoteResponse = from_binary(&bin).unwrap();
        assert!(res.vote.is_some());

        // bad query oops
        let msg = QueryMsg::Vote {
            poll_id: "BAD_ID".to_string(),
            address: ADDR1.to_string(),
        };
        let bin = query(deps.as_ref(), env, msg).unwrap();
        let res: VoteResponse = from_binary(&bin).unwrap();
        assert!(res.vote.is_none());
    }
}
