import pytest
from parser.engine import parse_line

def test_parse_valid_ssh_line():
    """Test that a standard SSH log line is parsed correctly."""
    log_line = "Feb 03 12:00:00 server sshd[123]: Failed password for ritam from 192.168.1.1 port 22 ssh2"
    entry = parse_line(log_line)
    
    assert entry is not None
    assert entry.timestamp == "Feb 03 12:00:00"
    assert entry.status == "Failed"
    assert entry.username == "ritam"
    assert entry.ip_address == "192.168.1.1"

def test_parse_valid_accepted_line():
    """Test that an 'Accepted' password line is parsed correctly."""
    log_line = "Feb 03 12:05:00 server sshd[123]: Accepted password for admin from 10.0.0.5 port 22 ssh2"
    entry = parse_line(log_line)
    
    assert entry is not None
    assert entry.status == "Accepted"
    assert entry.username == "admin"

def test_ghost_user_line():
    """Test the 'Ghost Line' case where the username is empty (double space)."""
    log_line = "Feb 03 12:10:00 server sshd[124]: Failed password for  from 192.168.1.1 port 22 ssh2"
    entry = parse_line(log_line)
    
    assert entry is not None
    assert entry.username == ""
    assert entry.ip_address == "192.168.1.1"

def test_ui_injection_attempt():
    """Test that a username with spaces or brackets is captured raw (sanitization happens in UI)."""
    log_line = "Feb 03 12:15:00 server sshd[125]: Failed password for [bold red]admin[/bold red] from 1.2.3.4 port 22 ssh2"
    entry = parse_line(log_line)
    
    assert entry is not None
    assert entry.username == "[bold red]admin[/bold red]" 

def test_invalid_user_prefix():
    """Test logs that include the 'invalid user' prefix."""
    log_line = "Feb 03 12:20:00 server sshd[126]: Failed password for invalid user hacker from 1.2.3.4 port 22 ssh2"
    entry = parse_line(log_line)
    
    assert entry is not None
    assert entry.username == "hacker"

def test_malformed_line():
    """Test that random garbage text returns None."""
    log_line = "This is just a random sentence, not a log line."
    entry = parse_line(log_line)
    
    assert entry is None