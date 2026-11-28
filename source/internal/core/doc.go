// Package core is the base of netdir that every other part builds on: the configuration and its checks, the gateway engines
// (VRRP, CARP, anycast, BGP, OSPF), the supervisor and its device checks, the network tools (ping, dig, scan, whois), SNMP and
// LLDP, certificates, backups, updates, captures, and the small helpers they share.  The device drivers are the separate
// package netdir/device.
package core
