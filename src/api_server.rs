mod api;
mod version;

use hbb_common::{bail, log, tokio, ResultType};
use std::{env, io::{BufRead, Write}};

enum AdminCmd {
    AddUser,
    SetPassword,
    DisableUser,
    EnableUser,
}

struct Options {
    port: i32,
    db_path: String,
    trusted_proxy: bool,
}

fn parse_options(args: &[String], from: usize) -> ResultType<Options> {
    let mut opts = Options {
        port: 21115,
        db_path: "api.sqlite3".to_owned(),
        trusted_proxy: false,
    };
    let mut i = from;
    while i < args.len() {
        match args[i].as_str() {
            "-p" | "--port" => {
                i += 1;
                if i >= args.len() {
                    bail!("缺少端口参数");
                }
                opts.port = args[i].parse().unwrap_or(0);
            }
            "-d" | "--db" => {
                i += 1;
                if i >= args.len() {
                    bail!("缺少数据库路径参数");
                }
                opts.db_path = args[i].clone();
            }
            "-t" | "--trusted-proxy" => opts.trusted_proxy = true,
            _ => bail!("未知参数: {}", args[i]),
        }
        i += 1;
    }
    if opts.port == 0 {
        opts.port = 21115;
    }
    Ok(opts)
}

fn main() -> ResultType<()> {
    let args: Vec<String> = env::args().collect();
    let cmd = match args.get(1).map(|x| x.as_str()) {
        Some("--add-user") => Some(AdminCmd::AddUser),
        Some("--set-password") => Some(AdminCmd::SetPassword),
        Some("--disable-user") => Some(AdminCmd::DisableUser),
        Some("--enable-user") => Some(AdminCmd::EnableUser),
        _ => None,
    };
    if let Some(cmd) = cmd {
        let username = match args.get(2) {
            Some(u) => u.clone(),
            None => bail!("缺少用户名"),
        };
        let opts = parse_options(&args, 3)?;
        let rt = tokio::runtime::Runtime::new()?;
        rt.block_on(admin_cmd(&opts.db_path, &username, cmd))
    } else {
        let opts = parse_options(&args, 1)?;
        let port = opts.port;
        let db_path = opts.db_path;
        let trusted_proxy = opts.trusted_proxy;
        let rt = tokio::runtime::Runtime::new()?;
        rt.block_on(api::start_server(port, &db_path, trusted_proxy))
    }
}

async fn admin_cmd(db_path: &str, username: &str, cmd: AdminCmd) -> ResultType<()> {
    let db = api::open_db(db_path).await?;
    match cmd {
        AdminCmd::AddUser => {
            let pwd = read_pwd()?;
            let pwd2 = read_pwd()?;
            if pwd != pwd2 {
                log::error!("两次输入的密码不一致");
                std::process::exit(1);
            }
            api::add_user(&db, username, &pwd).await?;
        }
        AdminCmd::SetPassword => {
            let pwd = read_pwd()?;
            api::set_password(&db, username, &pwd).await?;
        }
        AdminCmd::DisableUser => api::set_user_enabled(&db, username, false).await?,
        AdminCmd::EnableUser => api::set_user_enabled(&db, username, true).await?,
    }
    Ok(())
}

fn read_pwd() -> ResultType<String> {
    print!("请输入密码: ");
    std::io::stdout().flush()?;
    let mut line = String::new();
    std::io::stdin().lock().read_line(&mut line)?;
    Ok(line.trim().to_owned())
}