use tokio::sync::mpsc::{channel, Sender, Receiver};
use tokio::sync::mpsc::error::SendError;
use tokio::time::{sleep, Duration};
use log::{warn};

#[derive(Clone)]
pub struct MonitoredSender<T> {
    pub inner: Sender<T>,
    _tag: String,
    _level: String,
}

impl <T> MonitoredSender<T> 
where T: Send + 'static {
    pub fn new(
        sender: Sender<T>,     
        tag: String,
        level: String,
    ) -> Self {
        let sender_copy = sender.clone();
        let tag_copy = tag.clone();
        let level_copy = level.clone();
        tokio::spawn(async move {
            MonitoredSender::log(sender_copy, tag_copy, level_copy).await;
        });

        Self {
            inner: sender.clone(),
            _tag: tag,
            _level: level,
        }
    }

    pub async fn send(&self, msg: T) -> Result<(), SendError<T>> {
        self.inner.send(msg).await
    }

    async fn log(sender: Sender<T>, tag: String, _level: String) {
        loop {
            sleep(Duration::from_millis(60_000)).await;
            if sender.is_closed() {
                break;
            }
            // if level == "debug" {
            //     debug!("[{}] remaining capacity: {}", tag, sender.capacity());
            // }
            // else {
            //     info!("[{}] remaining capacity: {}", tag, sender.capacity());
            // }
            if sender.capacity() == 0 {
                warn!("[{}] Low remaining capacity: {}", tag, sender.capacity());
            }
        }
    }
}


#[derive(Clone)]
pub struct MonitoredChannel;

impl MonitoredChannel {
    pub fn new<T: Send + 'static>(capacity: usize, tag: String, level: &str) -> (MonitoredSender<T>, Receiver<T>) {
        let (sender, receiver) = channel(capacity);

        let channel = MonitoredSender::new(
            sender,
            tag,
            level.to_string(),
        );

        (channel, receiver)
    }


}
