use std::io::{IsTerminal, Read, Write};
use std::path::PathBuf;
use std::process::{Command as ProcCommand, ExitCode};

use clap::{Args, Parser, Subcommand};
use envvault::error::{Error, Result};
use envvault::vault::Vault;
use envvault::{crypto, session};

#[derive(Parser)]
#[command(
    name = "envvault",
    version,
    about = "EnvVault — secure environment & credential management",
    long_about = "Store API keys, environment variables, database credentials and SSH keys\nin an encrypted local vault, and inject them into processes without\nplaintext .env files."
)]
struct Cli {
    /// Path to the vault database
    #[arg(long, global = true, env = "ENVVAULT_VAULT")]
    vault: Option<PathBuf>,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Create a new encrypted vault
    Init,
    /// Unlock the vault with the master password
    Unlock,
    /// Lock the vault and discard the active session
    Lock,
    /// Show vault status
    Status,

    /// Manage projects
    Project {
        #[command(subcommand)]
        command: ProjectCommand,
    },
    /// Manage environments
    Env {
        #[command(subcommand)]
        command: EnvCommand,
    },
    /// Manage secrets
    Secret {
        #[command(subcommand)]
        command: SecretCommand,
    },

    /// Set a secret value (alias for 'envvault secret set')
    Set(SetArgs),
    /// Print a decrypted secret (alias for 'envvault secret get')
    Get(GetArgs),
    /// List secrets (alias for 'envvault secret list')
    List(ListArgs),

    /// Run a command with secrets injected as environment variables
    Run(RunArgs),

    /// Show the audit log (never contains secret values)
    Audit,
    /// Copy the encrypted vault database to a backup file
    Backup { destination: PathBuf },

    /// Import secrets from a plaintext .env file
    Import(ImportArgs),
    /// Export secrets to a plaintext .env file (requires confirmation)
    Export(ExportArgs),
}

#[derive(Subcommand)]
enum ProjectCommand {
    /// Create a project
    Create {
        name: String,
        #[arg(default_value = "")]
        description: String,
    },
    /// List projects
    List,
    /// Delete a project and all its secrets
    Delete { name: String },
}

#[derive(Subcommand)]
enum EnvCommand {
    /// Create an environment in a project
    Create {
        project: String,
        environment: String,
    },
    /// List environments of a project
    List { project: String },
}

#[derive(Subcommand)]
enum SecretCommand {
    /// Set a secret value (reads the value from stdin, or prompts)
    Set(SetArgs),
    /// Print a decrypted secret value to stdout
    Get(GetArgs),
    /// List secret metadata (values stay hidden)
    List(ListArgs),
    /// Delete a secret
    Delete(GetArgs),
}

#[derive(Args)]
struct SetArgs {
    project: String,
    name: String,
    /// Environment name
    #[arg(long = "env", default_value = "development")]
    env: String,
    /// Secret type (api-key, database, variable, secret)
    #[arg(long, default_value = "secret")]
    r#type: String,
    /// Secret description
    #[arg(long, default_value = "")]
    description: String,
}

#[derive(Args)]
struct GetArgs {
    project: String,
    name: String,
    /// Environment name
    #[arg(long = "env", default_value = "development")]
    env: String,
}

#[derive(Args)]
struct ListArgs {
    project: String,
    /// Environment name
    #[arg(long = "env", default_value = "development")]
    env: String,
}

#[derive(Args)]
struct RunArgs {
    project: String,
    /// Environment whose secrets are injected
    #[arg(long = "env", default_value = "development")]
    env: String,
    /// The command to run, after `--`
    #[arg(last = true, required = true)]
    command: Vec<String>,
}

#[derive(Args)]
struct ImportArgs {
    file: PathBuf,
    /// Target project
    #[arg(long)]
    project: String,
    /// Target environment (created if missing)
    #[arg(long = "env", default_value = "development")]
    env: String,
}

#[derive(Args)]
struct ExportArgs {
    project: String,
    /// Source environment
    #[arg(long = "env", default_value = "development")]
    env: String,
    /// Output file (default .env)
    #[arg(short, long)]
    output: Option<PathBuf>,
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    match run(cli) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::FAILURE
        }
    }
}

fn run(cli: Cli) -> Result<()> {
    match cli.command {
        Command::Init => cmd_init(cli.vault),
        Command::Unlock => cmd_unlock(cli.vault),
        Command::Lock => {
            session::clear()?;
            println!("Vault locked.");
            Ok(())
        }
        Command::Status => cmd_status(cli.vault),
        Command::Project { command } => match command {
            ProjectCommand::Create { name, description } => with_vault(cli.vault, |v| {
                let p = v.create_project(&name, &description)?;
                println!("Project '{}' created.", p.name);
                Ok(())
            }),
            ProjectCommand::List => with_vault(cli.vault, |v| {
                let projects = v.list_projects()?;
                if projects.is_empty() {
                    println!("No projects yet. Create one with: envvault project create <name>");
                    return Ok(());
                }
                println!("{:<20} {:>6} {:>8}  CREATED", "PROJECT", "ENVS", "SECRETS");
                for p in projects {
                    println!(
                        "{:<20} {:>6} {:>8}  {}",
                        p.name,
                        p.environments,
                        p.secrets,
                        p.created_at.chars().take(10).collect::<String>()
                    );
                }
                Ok(())
            }),
            ProjectCommand::Delete { name } => with_vault(cli.vault, |v| {
                let p = v.get_project(&name)?;
                if !confirm(&format!("Delete project '{}' and all its secrets?", p.name))? {
                    println!("Aborted.");
                    return Ok(());
                }
                v.delete_project(&p.name)?;
                println!("Project '{}' deleted.", p.name);
                Ok(())
            }),
        },
        Command::Env { command } => match command {
            EnvCommand::Create {
                project,
                environment,
            } => with_vault(cli.vault, |v| {
                let e = v.create_environment(&project, &environment)?;
                println!("Environment '{}' created in '{project}'.", e.name);
                Ok(())
            }),
            EnvCommand::List { project } => with_vault(cli.vault, |v| {
                let envs = v.list_environments(&project)?;
                if envs.is_empty() {
                    println!(
                        "No environments yet. Create one with: envvault env create <project> <env>"
                    );
                    return Ok(());
                }
                println!("{:<20} {:>8}  CREATED", "ENVIRONMENT", "SECRETS");
                for e in envs {
                    println!(
                        "{:<20} {:>8}  {}",
                        e.name,
                        e.secrets,
                        e.created_at.chars().take(10).collect::<String>()
                    );
                }
                Ok(())
            }),
        },
        Command::Secret { command } => match command {
            SecretCommand::Set(args) => cmd_set(cli.vault, args),
            SecretCommand::Get(args) => cmd_get(cli.vault, args),
            SecretCommand::List(args) => cmd_list(cli.vault, args),
            SecretCommand::Delete(args) => with_vault(cli.vault, |v| {
                if !confirm(&format!(
                    "Delete secret '{}' from {}/{}?",
                    args.name, args.project, args.env
                ))? {
                    println!("Aborted.");
                    return Ok(());
                }
                v.delete_secret(&args.project, &args.env, &args.name)?;
                println!("Secret deleted.");
                Ok(())
            }),
        },
        Command::Set(args) => cmd_set(cli.vault, args),
        Command::Get(args) => cmd_get(cli.vault, args),
        Command::List(args) => cmd_list(cli.vault, args),
        Command::Run(args) => cmd_run(cli.vault, args),
        Command::Audit => with_vault(cli.vault, |v| {
            let entries = v.list_audit(50)?;
            if entries.is_empty() {
                println!("Audit log is empty.");
                return Ok(());
            }
            println!("{:<9} {:<20} {:<28} RESULT", "TIME", "ACTION", "RESOURCE");
            for e in entries {
                let time = e.time.chars().skip(11).take(8).collect::<String>();
                println!(
                    "{:<9} {:<20} {:<28} {}",
                    time, e.action, e.resource, e.result
                );
            }
            Ok(())
        }),
        Command::Backup { destination } => {
            let path = resolve_vault_path(cli.vault)?;
            if !Vault::exists(&path) {
                return Err(Error::VaultNotFound);
            }
            std::fs::copy(&path, &destination)?;
            println!("Encrypted vault backed up to {}", destination.display());
            Ok(())
        }
        Command::Import(args) => cmd_import(cli.vault, args),
        Command::Export(args) => cmd_export(cli.vault, args),
    }
}

// --- commands ---------------------------------------------------------------

fn cmd_init(vault_flag: Option<PathBuf>) -> Result<()> {
    let path = resolve_vault_path(vault_flag)?;
    if Vault::exists(&path) {
        return Err(Error::VaultExists(path.display().to_string()));
    }

    let password = match std::env::var("ENVVAULT_PASSWORD") {
        Ok(p) => p.into_bytes(),
        Err(_) => {
            let pw = rpassword::prompt_password("New master password: ")?;
            let confirm_pw = rpassword::prompt_password("Confirm master password: ")?;
            if pw != confirm_pw {
                return Err(Error::Invalid("passwords do not match".into()));
            }
            pw.into_bytes()
        }
    };
    crypto::validate_password(&password)?;

    let vault = Vault::create(&path, &password)?;
    vault.save_session()?;
    println!("Vault created at {}", path.display());
    println!("Vault is unlocked for this session.");
    Ok(())
}

fn cmd_unlock(vault_flag: Option<PathBuf>) -> Result<()> {
    let path = resolve_vault_path(vault_flag)?;
    if !Vault::exists(&path) {
        return Err(Error::VaultNotFound);
    }
    let password = match std::env::var("ENVVAULT_PASSWORD") {
        Ok(p) => p.into_bytes(),
        Err(_) => rpassword::prompt_password("Master password: ")?.into_bytes(),
    };
    let vault = Vault::open(&path, &password)?;
    vault.audit("Vault unlocked", "", "success");
    vault.save_session()?;
    println!("Vault unlocked.");
    Ok(())
}

fn cmd_status(vault_flag: Option<PathBuf>) -> Result<()> {
    let path = resolve_vault_path(vault_flag)?;
    println!("Vault: {}", path.display());
    if !Vault::exists(&path) {
        println!("State: not initialised (run 'envvault init')");
        return Ok(());
    }
    match session::load(Some(&path)) {
        Ok(vault) => {
            let stats = vault.stats()?;
            println!("State: unlocked");
            println!(
                "Projects: {}   Environments: {}   Secrets: {}",
                stats.projects, stats.environments, stats.secrets
            );
            Ok(())
        }
        Err(Error::NoSession) | Err(Error::SessionExpired) => {
            println!("State: locked");
            Ok(())
        }
        Err(e) => Err(e),
    }
}

fn cmd_set(vault_flag: Option<PathBuf>, args: SetArgs) -> Result<()> {
    with_vault(vault_flag, |v| {
        if std::io::stdin().is_terminal() {
            let value = rpassword::prompt_password("Value: ")?;
            let s = v.set_secret(
                &args.project,
                &args.env,
                &args.name,
                &args.r#type,
                &args.description,
                value.as_bytes(),
            )?;
            print_set_result(&args, &args.env, s.version);
        } else {
            let value = read_line("value")?;
            let s = v.set_secret(
                &args.project,
                &args.env,
                &args.name,
                &args.r#type,
                &args.description,
                &value,
            )?;
            print_set_result(&args, &args.env, s.version);
        }
        Ok(())
    })
}

fn print_set_result(args: &SetArgs, env: &str, version: i64) {
    if version == 1 {
        println!("Secret '{}' stored in {}/{}.", args.name, args.project, env);
    } else {
        println!("Secret '{}' updated (version {version}).", args.name);
    }
}

fn cmd_get(vault_flag: Option<PathBuf>, args: GetArgs) -> Result<()> {
    with_vault(vault_flag, |v| {
        let (value, _) = v.get_secret_value(&args.project, &args.env, &args.name)?;
        let mut stdout = std::io::stdout();
        stdout.write_all(&value)?;
        stdout.write_all(b"\n")?;
        Ok(())
    })
}

fn cmd_list(vault_flag: Option<PathBuf>, args: ListArgs) -> Result<()> {
    with_vault(vault_flag, |v| {
        let secrets = v.list_secrets(&args.project, &args.env)?;
        if secrets.is_empty() {
            println!("No secrets in this environment.");
            return Ok(());
        }
        println!("{:<24} {:<14} {:>7}  UPDATED", "NAME", "TYPE", "VERSION");
        for s in secrets {
            println!(
                "{:<24} {:<14} {:>7}  {}",
                s.name,
                s.secret_type,
                s.version,
                s.updated_at
                    .chars()
                    .take(16)
                    .collect::<String>()
                    .replace('T', " ")
            );
        }
        Ok(())
    })
}

fn cmd_run(vault_flag: Option<PathBuf>, args: RunArgs) -> Result<()> {
    with_vault(vault_flag, |v| {
        let secrets = v.list_secrets(&args.project, &args.env)?;
        if secrets.is_empty() {
            return Err(Error::Invalid(format!(
                "no secrets in {}/{}",
                args.project, args.env
            )));
        }

        let mut env_vars: Vec<(String, String)> = std::env::vars().collect();
        for s in &secrets {
            let (value, _) = v.get_secret_value(&args.project, &args.env, &s.name)?;
            env_vars.push((s.name.clone(), String::from_utf8_lossy(&value).into_owned()));
        }

        v.audit(
            "Environment run",
            &format!("{}/{}", args.project, args.env),
            "success",
        );

        let (program, program_args) = args.command.split_first().expect("required by clap");
        let mut child = ProcCommand::new(program);
        child.args(program_args).envs(env_vars);
        let status = child
            .status()
            .map_err(|e| Error::Invalid(format!("failed to run '{program}': {e}")))?;
        if !status.success() {
            std::process::exit(status.code().unwrap_or(1));
        }
        Ok(())
    })
}

fn cmd_import(vault_flag: Option<PathBuf>, args: ImportArgs) -> Result<()> {
    let pairs = parse_env_file(&args.file)?;
    eprintln!("Warning: importing this file will read plaintext secrets.");
    eprintln!("Source:  {}", args.file.display());
    eprintln!("{} secrets detected.", pairs.len());
    eprintln!("After import, EnvVault will not delete the original file.");
    if !confirm("Continue?")? {
        println!("Aborted.");
        return Ok(());
    }

    with_vault(vault_flag, |v| {
        v.get_project(&args.project)?;
        if v.get_environment(&args.project, &args.env).is_err() {
            v.create_environment(&args.project, &args.env)?;
        }
        for pair in &pairs {
            v.set_secret(
                &args.project,
                &args.env,
                &pair.name,
                "secret",
                "",
                pair.value.as_bytes(),
            )?;
        }
        v.audit(
            "Import",
            &format!("{}/{}", args.project, args.env),
            "success",
        );
        println!(
            "Imported {} secrets into {}/{}.",
            pairs.len(),
            args.project,
            args.env
        );
        println!("Remember to delete the plaintext file yourself when you no longer need it.");
        Ok(())
    })
}

fn cmd_export(vault_flag: Option<PathBuf>, args: ExportArgs) -> Result<()> {
    with_vault(vault_flag, |v| {
        let secrets = v.list_secrets(&args.project, &args.env)?;
        if secrets.is_empty() {
            return Err(Error::Invalid(format!(
                "no secrets in {}/{}",
                args.project, args.env
            )));
        }
        let output = args.output.unwrap_or_else(|| PathBuf::from(".env"));

        eprintln!(
            "Warning: this will create a PLAINTEXT file containing {} secrets.",
            secrets.len()
        );
        eprintln!("Destination: {}", output.display());
        if !confirm("Continue?")? {
            println!("Aborted.");
            return Ok(());
        }

        let mut file = std::fs::File::create(&output)?;
        for s in &secrets {
            let (value, _) = v.get_secret_value(&args.project, &args.env, &s.name)?;
            writeln!(
                file,
                "{}={}",
                s.name,
                String::from_utf8_lossy(&value).replace('\n', "\\n")
            )?;
        }
        v.audit(
            "Export",
            &format!("{}/{}", args.project, args.env),
            "success",
        );
        println!("Exported {} secrets to {}", secrets.len(), output.display());
        Ok(())
    })
}

// --- helpers ----------------------------------------------------------------

fn with_vault<F>(vault_flag: Option<PathBuf>, f: F) -> Result<()>
where
    F: FnOnce(&Vault) -> Result<()>,
{
    let path = resolve_vault_path(vault_flag)?;
    let vault = session::load(Some(&path))?;
    f(&vault)
}

fn resolve_vault_path(vault_flag: Option<PathBuf>) -> Result<PathBuf> {
    if let Some(p) = vault_flag {
        return Ok(p);
    }
    Vault::default_path()
}

fn confirm(question: &str) -> Result<bool> {
    eprint!("{question} [y/N] ");
    let _ = std::io::stderr().flush();
    let mut line = String::new();
    std::io::stdin().read_line(&mut line)?;
    let answer = line.trim().to_lowercase();
    Ok(answer == "y" || answer == "yes")
}

/// Reads a secret value: masked prompt on a TTY, single line from stdin
/// otherwise (for piping).
fn read_value() -> Result<Vec<u8>> {
    if std::io::stdin().is_terminal() {
        Ok(rpassword::prompt_password("Value: ")?.into_bytes())
    } else {
        let mut buf = Vec::new();
        std::io::stdin().read_to_end(&mut buf)?;
        while buf.last().is_some_and(|b| *b == b'\n' || *b == b'\r') {
            buf.pop();
        }
        Ok(buf)
    }
}

fn read_line(what: &str) -> Result<Vec<u8>> {
    read_value().map_err(|e| match e {
        Error::Io(_) => Error::Invalid(format!("failed to read {what}")),
        other => other,
    })
}

#[derive(Debug)]
struct EnvPair {
    name: String,
    value: String,
}

/// Parses KEY=VALUE lines, ignoring blanks, comments and `export ` prefixes.
fn parse_env_file(path: &PathBuf) -> Result<Vec<EnvPair>> {
    let data = std::fs::read_to_string(path)?;
    let mut pairs = Vec::new();
    for (idx, raw) in data.lines().enumerate() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let line = line.strip_prefix("export ").unwrap_or(line);
        let Some(eq) = line.find('=') else {
            return Err(Error::Invalid(format!(
                "{}:{}: expected KEY=VALUE",
                path.display(),
                idx + 1
            )));
        };
        let name = line[..eq].trim().to_string();
        let value = unquote(line[eq + 1..].trim());
        pairs.push(EnvPair { name, value });
    }
    if pairs.is_empty() {
        return Err(Error::Invalid(format!(
            "{}: no secrets detected",
            path.display()
        )));
    }
    Ok(pairs)
}

fn unquote(v: &str) -> String {
    let bytes = v.as_bytes();
    if v.len() >= 2
        && ((bytes[0] == b'"' && bytes[v.len() - 1] == b'"')
            || (bytes[0] == b'\'' && bytes[v.len() - 1] == b'\''))
    {
        v[1..v.len() - 1].to_string()
    } else {
        v.to_string()
    }
}
