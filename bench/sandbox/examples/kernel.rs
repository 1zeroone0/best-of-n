fn main() {
    for (a, b) in [(1, 2), (5, 3), (7, 7)] { println!("max {a} {b} = {}", kernel::max(a, b)); }
    println!("double 9 = {}", kernel::double(9));
    println!("pick 1 2 = {}", kernel::pick(1, 2));
}
