# Import necessary libraries
import requests
from pathlib import Path
from zipfile import ZipFile
from dataclasses import dataclass


@dataclass
class Feed:
    recent_path: Path
    full_feed_path: Path
    recent_feed_url: str
    full_feed_url: str


def fetch_csv_feed(feed: Feed) -> None:
    """
    Fetches the CSV feed from the provided URL and saves it to the specified path.

    If the CSV file already exists, it fetches the recent CSV feed. Otherwise, it fetches the full CSV feed,
    extracts the contents of the zip file, and renames the extracted CSV file to the original CSV file name.

    Args:
        feed (Feed): An instance of the Feed dataclass.

    Returns:
        None
    """

    # Check if the CSV file already exists
    if feed.recent_path.exists():
        # If it exists, fetch the recent CSV feed
        response = requests.get(feed.recent_feed_url)
        # Write the response content to the CSV file
        with feed.recent_path.open("wb") as file:
            file.write(response.content)
    else:
        # If it doesn't exist, fetch the full CSV feed
        response = requests.get(feed.full_feed_url)
        # Create a zip file path by appending ".zip" to the CSV file path
        zip_file = feed.recent_path.with_suffix(".zip")
        # Write the response content to the zip file
        with zip_file.open("wb") as file:
            file.write(response.content)

        # Extract the contents of the zip file to the parent directory of the CSV file
        with ZipFile(zip_file, "r") as zip_ref:
            zip_ref.extractall(feed.recent_path.parent)

        # Delete the zip file
        zip_file.unlink()

        # Rename the extracted CSV file to the original CSV file name
        feed.full_feed_path.rename(feed.recent_path)


def main():
    # Get the current working directory
    current_directory = Path(".")

    # Create feeds
    feeds = [
        # threatfox
        Feed(
            current_directory / "threatfox.csv",
            current_directory / "full.csv",
            "https://threatfox.abuse.ch/export/csv/recent/",
            "https://threatfox.abuse.ch/export/csv/full/",
        ),
        # malwarebazaar
        Feed(
            current_directory / "malwarebazaar.csv",
            current_directory / "full.csv",
            "https://bazaar.abuse.ch/export/csv/recent/",
            "https://bazaar.abuse.ch/export/csv/full/",
        ),
        # URLhaus
        Feed(
            current_directory / "urlhaus.csv",
            current_directory / "csv.txt",
            "https://urlhaus.abuse.ch/downloads/csv_recent/",
            "https://urlhaus.abuse.ch/downloads/csv/",
        ),
    ]

    # Fetch the CSV feeds
    for feed in feeds:
        fetch_csv_feed(feed)


if __name__ == "__main__":
    main()
