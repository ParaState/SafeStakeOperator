use tokio::sync::mpsc::{channel, Sender, Receiver};
use tokio::sync::mpsc::error::SendError;
use tokio::time::{sleep, Duration};
use log::{info};

#[derive(Clone)]
pub struct MonitoredSender<T> {
    pub inner: Sender<T>,
}

impl <T> MonitoredSender<T> {
    pub fn new(sender: Sender<T>) -> Self {
        Self {inner: sender}
    }

    pub async fn send(&self, msg: T) -> Result<(), SendError<T>> {
        self.inner.send(msg).await
    }
}

#[derive(Clone)]
pub struct MonitoredChannel<T: Send> {
    channel: Sender<T>,
    tag: String,
}

impl<T> MonitoredChannel<T>
where T: Send + 'static {
    pub fn new(capacity: usize, tag: String) -> (MonitoredSender<T>, Receiver<T>) {
        let (sender, receiver) = channel(capacity);

        let channel = MonitoredChannel{
            channel: sender.clone(),
            tag,
        };
        tokio::spawn(async move {
            channel.log().await;
        });

        (MonitoredSender::new(sender), receiver)
    }

    async fn log(&self) {
        loop {
            sleep(Duration::from_millis(60_000)).await;
            info!("[{}] remaining capacity: {}", self.tag, self.channel.capacity());
        }
    }
}
