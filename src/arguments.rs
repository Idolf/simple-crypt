use clap::AppSettings;

#[derive(StructOpt, Debug)]
#[structopt(name = "simple-crypt", about = "Super-simple encryption")]
#[structopt(global_setting_raw = "AppSettings::ColoredHelp")]
#[structopt(global_setting_raw = "AppSettings::DeriveDisplayOrder")]
#[structopt(global_setting_raw = "AppSettings::GlobalVersion")]
#[structopt(global_setting_raw = "AppSettings::InferSubcommands")]
#[structopt(global_setting_raw = "AppSettings::ArgRequiredElseHelp")]
pub enum Cmd {
    #[structopt(name = "keys",
                about = "Commands about keys (such as generating or re-encrypting)")]
    Keys {
        #[structopt(subcommand)] cmd: KeyCmd,
    },
    #[structopt(name = "encrypt", about = "Encrypts a file")]
    Encrypt {
        #[structopt(help = "Public key")] public_key: String,
        #[structopt(help = "Plaintext file")] input_file: String,
        #[structopt(help = "Ciphertext file")] output_file: String,
    },
    #[structopt(name = "decrypt", about = "Decrypts a file")]
    Decrypt {
        #[structopt(help = "Keyfile")] keyfile: String,
        #[structopt(help = "Ciphertext file")] input_file: String,
        #[structopt(help = "Plaintext file")] output_file: String,
    },
}

#[derive(StructOpt, Debug)]
pub enum KeyCmd {
    #[structopt(name = "generate", about = "Generates a new key")]
    Gen {
        #[structopt(help = "Output secret key file")] keyfile: String,
        #[structopt(long = "password-ops-limit", help = "Set ops limit for hashing the password")]
        password_ops_limit: Option<usize>,
        #[structopt(long = "password-mem-limit",
                    help = "Set mem limit (in bytes) for hashing the password")]
        password_mem_limit: Option<usize>,
    },
    #[structopt(name = "publickey", about = "Prints the public key from a secret key")]
    PrintPublickey {
        #[structopt(help = "Keyfile")] keyfile: String,
    },
    #[structopt(name = "password", about = "Changes the password for a keyfile")]
    ChangePassword {
        #[structopt(help = "Output secret key file")] keyfile: String,
        #[structopt(long = "password-ops-limit", help = "Set ops limit for hashing the password")]
        password_ops_limit: Option<usize>,
        #[structopt(long = "password-mem-limit",
                    help = "Set mem limit (in bytes) for hashing the password")]
        password_mem_limit: Option<usize>,
    },
}
