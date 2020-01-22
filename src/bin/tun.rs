use udarnik::tun::linux::UtunDev;

fn main() {
    let (dev, _, _) = UtunDev::new("tun%d").unwrap();
    println!("{:?}", dev.name());
}
