// Credit: Demo Z/8Z by Zama (https://github.com/zama-ai/demo_z8z ; modified)
// This macro allows to compute the duration of the execution of the expressions enclosed.
// Note that the variables are not captured.
#[macro_export]
macro_rules! measure_duration {
    ($title: literal, [$($block: tt)+]) => {
        info!("{} ... ", $title);
        let __now = std::time::SystemTime::now();
        $(
           $block
        )+
        let __time = __now.elapsed().unwrap().as_millis() as f64;
        let __s_time = if __time < 1_000. {
            format!("{} ms", __time)
        } else {
            format!("{} {}", __time / 1_000., String::from("s").bold())
        };
        println!("{} (in {})", String::from("OK").green().bold(), __s_time);
    }
}

// Parmesan logging macros
#[macro_export]
macro_rules! info {
    ($($arg:tt)*) => {
        let msg = parm_format_info!($($arg)*);
        eprint!("{}", msg);
        io::stdout().flush().unwrap();
    }
}
#[macro_export]
macro_rules! infoln {
    ($($arg:tt)*) => {
        let msg = parm_format_info!($($arg)*);
        eprintln!("{}", msg);
    }
}

#[macro_export]
macro_rules! parm_error {
    ($($arg:tt)*) => {
        let msg = parm_format_err!($($arg)*);
        eprintln!("{}", msg);
    }
}

#[macro_export]
macro_rules! parm_format_info {
    ($($arg:tt)*) => {{
        let mut msg = format!($($arg)*);
        msg = format!("🧀 {} {}", String::from(">").yellow().bold(), msg);
        msg = msg.replace("\n", "\n     ");
        msg
    }}
}
#[macro_export]
macro_rules! parm_format_err {
    ($($arg:tt)*) => {{
        let mut msg = format!($($arg)*);
        msg = format!("🫕  {}{}", String::from("> Fondue!\n").red().bold(), msg);
        msg = msg.replace("\n", "\n     ");
        // does not work this way: msg = msg.replace("\n", String::from("\n     ").red().bold().as_str());
        msg = format!("{}\n{}", msg, String::from("-----").red().bold());
        msg
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
