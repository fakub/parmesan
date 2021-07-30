// Credit: Demo Z/8Z by Zama (https://github.com/zama-ai/demo_z8z ; modified)
// This macro allows to compute the duration of the execution of the expressions enclosed.
// Note that the variables are not captured.
#[macro_export]
macro_rules! measure_duration {
    ($title:literal, [$($block:tt)+]) => {
        // write title
        crate::infoln!("{} ... ", $title);
        // increase log level
        unsafe {
            if crate::LOG_LVL < u8::MAX {crate::LOG_LVL += 1;}
        }
        // run block
        let __now = std::time::SystemTime::now();
        $(
           $block
        )+
        // get elapsed time
        let __time = __now.elapsed().unwrap().as_millis() as f64;
        let __s_time = if __time < 1_000. {
            String::from(format!("{} ms", __time)        ).blue()
        } else {
            String::from(format!("{} s", __time / 1_000.)).blue().bold()
        };
        // decrease log level back
        unsafe {
            if crate::LOG_LVL > 0 {crate::LOG_LVL -= 1;}
            let indent = format!("{}  └ ", "  │ ".repeat(crate::LOG_LVL as usize));
            let status = String::from("OK").green().bold();   // can be other statuses
            eprintln!("{}{} (in {})", indent, status, __s_time);
        }
    }
}

// Parmesan logging macros
//~ #[macro_export]
//~ macro_rules! info {
    //~ ($($arg:tt)*) => {
        //~ let msg = crate::parm_format_info!($($arg)*);
        //~ eprint!("{}", msg);
        //~ io::stderr().flush().unwrap();
    //~ }
//~ }
#[macro_export]
macro_rules! infoln {
    ($($arg:tt)*) => {
        let msg = crate::parm_format_info!($($arg)*);
        eprintln!("{}", msg);
    }
}
#[macro_export]
macro_rules! infobox {
    ($($arg:tt)*) => {
        let msg = crate::parm_format_infobox!($($arg)*);
        eprintln!("{}", msg);
    }
}

#[macro_export]
macro_rules! parm_error {
    ($($arg:tt)*) => {
        let msg = crate::parm_format_err!($($arg)*);
        eprintln!("{}", msg);
    }
}

// Parmesan message formatting macros
#[macro_export]
macro_rules! parm_format_info {
    ($($arg:tt)*) => {{
        unsafe {
            let mut msg = format!($($arg)*);
            // calc indentation
            let mut indent = "  │ ".repeat(crate::LOG_LVL as usize);
            msg = format!("{} 🧀 {}", indent, msg);
            indent = format!("\n{}    ", indent);
            msg = msg.replace("\n", &indent);
            msg
        }
    }}
}

#[macro_export]
macro_rules! parm_format_infobox {
    ($($arg:tt)*) => {{
        unsafe {
            let mut msg = format!($($arg)*);
            let mut ms = String::from(msg);
            ms.truncate(100);
            msg = ms.as_str().replace("\n", " | ");
            let top_of_box = format!("{}{}{}", String::from("┏").yellow(), String::from("━".repeat(msg.chars().count() + 4)).yellow(), String::from("┓").yellow(), );
            let bot_of_box = format!("{}{}{}", String::from("┗").yellow(), String::from("━".repeat(msg.chars().count() + 4)).yellow(), String::from("┛").yellow(), );
            msg = format!("    {}\n{}  {}  {}\n{}", top_of_box, String::from("┃").yellow(), msg, String::from("┃").yellow(), bot_of_box);
            // calc indentation
            let mut indent = "  │ ".repeat(crate::LOG_LVL as usize);
            msg = format!("{}{}", indent, msg);
            indent = format!("\n{}    ", indent);
            msg = msg.replace("\n", &indent);
            msg
        }
    }}
}

#[macro_export]
macro_rules! parm_format_err {
    ($($arg:tt)*) => {{
        unsafe {
            let mut msg = format!($($arg)*);
            // calc indentation
            let mut indent = "  ▒ ".repeat(crate::LOG_LVL as usize);
            // let mut indent = format!("{}", String::from("  X ").red().bold().repeat(crate::LOG_LVL as usize));   // does not work this way, format gets lost after repeat
            msg = format!("{} 🫕  {}{}", indent, String::from("ERR ").red().bold(), msg);
            indent = format!("\n{}        ", indent);
            msg = msg.replace("\n", &indent);
            //~ msg = format!("{}\n{}\n{}", String::from("-----").red().bold(), msg, String::from("-----").red().bold());
            msg
        }
    }}
}



// some examples of existing macros (modified):

//~ macro_rules! format {
    //~ ($($arg:tt)*) => {{
        //~ let res = $crate::fmt::format($crate::__export::format_args!($($arg)*));
        //~ res
    //~ }}
//~ }
//~ macro_rules! println {;
    //~ ($($arg:tt)*) => ({
        //~ $crate::io::_print($crate::format_args_nl!($($arg)*));
    //~ })
//~ }

//~ macro_rules! vec {
    //~ ( $( $x:expr ),* ) => {
        //~ {
            //~ let mut temp_vec = Vec::new();
            //~ $(
                //~ temp_vec.push($x);
            //~ )*
            //~ temp_vec
        //~ }
    //~ };
//~ }
