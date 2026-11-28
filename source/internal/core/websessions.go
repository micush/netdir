package core

// Sessions survive a restart of the daemon (an upgrade, a reboot), so nobody has to sign in again.
// They are kept in <state-dir>/sessions.json (0600).  Only a SHA-256 of each cookie value is stored, so
// the file cannot be used to take a session over.  The idle timeout and the 12 hour limit still apply
// to a restored session, and the group is re-checked on its first use.

const SessionsFile = "sessions.json"
