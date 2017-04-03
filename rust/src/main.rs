extern crate regex;

use std::io;
use regex::Regex;

fn main() {
   println!("Packet Analyzer - Rust version");

   let mut line = String::new();

//   let mut result = 
   let mut result = io::stdin().read_line(&mut line);//
println!("{}", line);
result.expect("Error");

   let mut end = false;
   while !end {
   	 line = String::new();
   	 result = io::stdin().read_line(&mut line);
    match result {
      Ok(0) => end = true,
      Ok(_) => {},
      Err(_) => end = true      
    }
    print!("{}", line);
    analyze(line);


    }
   
println!("END");
   
println!("\x1B[32mPLAYGROUND\x1B[0m")


        
}

// lines of form \s+0xDDDD: hex... to byte representation
fn analyze(line: String) {
   //let re = Regex::new(r"^\s*0x[0-9a-fA-H]{4}:\s+([0-9a-fA-H]\s+)\s*$").unwrap();
   //let re = Regex::new(r"^\s*0x([0-9a-fA-H]{4}):.*\s*$").unwrap();
   
//let re = Regex::new(r"^\s*0x([0-9a-fA-H]{4}):\s+([0-9a-fA-F]+\s+)+\s*$").unwrap();
let re = Regex::new(r"^\s*0x([0-9a-fA-H]{4}):\s+(.*)\s*$").unwrap();

let pare = Regex::new(r"^\s*([0-9a-fA-H]{2})(.*)$").unwrap();
   if re.is_match(line.as_str())
   {
	println!("\x1B[31mMATCH \x1B[0m<>");

/*
colors (from stackoverflow):
#define KNRM  "\x1B[0m"
#define KRED  "\x1B[31m"
#define KGRN  "\x1B[32m"
#define KYEL  "\x1B[33m"
#define KBLU  "\x1B[34m"
#define KMAG  "\x1B[35m"
#define KCYN  "\x1B[36m"
#define KWHT  "\x1B[37m"
*/
   	for c in re.captures_iter(line.as_str()) {
	    println!("{}; {} - {}", &c[1], c.len(),&c[2]);
 // todo: c[2].trim(). group2? .map(conversion).collect

	    for innercap in pare.captures_iter(&c[2]){
	    	println!("{}; rest = {} [of {}]", &innercap[1], &innercap[2], innercap.len());
	    }    
       }
   }
}
