use log::{info};

pub async fn test1() {

  let mut tick = tokio::time::interval(tokio::time::Duration::from_secs(1));
  tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
  tokio::time::sleep(tokio::time::Duration::from_secs(10)).await;
  info!("After sleep");
  tick.tick().await;
  info!("1 tick");
  tick.tick().await;
  info!("2 tick");
  tick.tick().await;
  info!("3 tick");
  tick.tick().await;
  info!("4 tick");
}

#[tokio::main]
async fn main() {
  let mut logger = env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info"));
  logger.format_timestamp_millis();
  logger.init();

  test1().await;
}