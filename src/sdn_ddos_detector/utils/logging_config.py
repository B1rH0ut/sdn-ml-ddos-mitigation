"""
Async logging configuration for the SDN DDoS detection controller.

Uses a Queue + QueueHandler + QueueListener pattern so that log writes
(especially to rotating files) never block green threads. The controller
calls setup_logging() once at startup and listener.stop() on shutdown.

Audit finding addressed:
    - 6.2: Synchronous attack log writes block green threads
"""

import logging
import logging.handlers
import os
import queue


def setup_logging(log_dir="logs/", level=logging.INFO):
    """
    Configure async logging with a QueueHandler and RotatingFileHandler.

    Creates a background thread (via QueueListener) that drains the
    queue and writes to a rotating log file. All logger.info/warning/etc
    calls go through the queue and return immediately.

    Args:
        log_dir: Directory for log files. Created if it doesn't exist.
        level: Logging level (default: INFO).

    Returns:
        QueueListener: The listener instance. Caller must call
            listener.stop() during graceful shutdown.
    """
    os.makedirs(log_dir, exist_ok=True)

    log_file = os.path.join(log_dir, 'controller.log')

    # Rotating file handler: 10 MB max, keep 5 backups
    file_handler = logging.handlers.RotatingFileHandler(
        log_file,
        maxBytes=10 * 1024 * 1024,  # 10 MB
        backupCount=5,
    )
    file_handler.setLevel(level)
    formatter = logging.Formatter(
        '%(asctime)s %(name)s %(levelname)s %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S',
    )
    file_handler.setFormatter(formatter)

    # Queue-based async handler
    log_queue = queue.Queue(-1)  # unbounded queue
    queue_handler = logging.handlers.QueueHandler(log_queue)
    queue_handler.setLevel(level)

    # Listener drains the queue in a background thread
    listener = logging.handlers.QueueListener(
        log_queue, file_handler, respect_handler_level=True
    )
    listener.start()

    # Attach the queue handler to the root logger
    root_logger = logging.getLogger()
    root_logger.addHandler(queue_handler)
    root_logger.setLevel(level)

    return listener
