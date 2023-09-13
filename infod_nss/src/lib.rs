#[macro_use]
extern crate lazy_static;

use std::fs::File;
use std::io::{BufRead, BufReader};
use std::net::IpAddr;

use color_eyre::eyre::Result;
use libnss::group::{Group, GroupHooks};
use libnss::host::{AddressFamily, Host, HostHooks};
use libnss::initgroups::InitgroupsHooks;
use libnss::interop::Response;
use libnss::passwd::{Passwd, PasswdHooks};
use libnss::shadow::{Shadow, ShadowHooks};
use libnss::{
    libnss_group_hooks, libnss_host_hooks, libnss_initgroups_hooks, libnss_passwd_hooks,
    libnss_shadow_hooks,
};

pub fn read_passwd<R>(reader: BufReader<R>) -> Result<Vec<Passwd>>
where
    R: std::io::Read,
{
    let mut users = Vec::new();
    for line in reader.lines() {
        let line = line?;
        let parts: Vec<_> = line.split(':').collect();
        users.push(Passwd {
            name: parts[0].to_string(),
            passwd: parts[1].to_string(),
            uid: parts[2].parse()?,
            gid: parts[3].parse()?,
            gecos: parts[4].to_string(),
            dir: parts[5].to_string(),
            shell: parts[6].to_string(),
        })
    }
    Ok(users)
}

pub fn read_shadow<R>(reader: BufReader<R>) -> Result<Vec<Shadow>>
where
    R: std::io::Read,
{
    let mut entries = Vec::new();
    for line in reader.lines() {
        let line = line?;
        let parts: Vec<_> = line.split(':').collect();
        entries.push(Shadow {
            name: parts[0].to_string(),
            passwd: parts[1].to_string(),
            last_change: parts[2].parse().unwrap_or(0),
            change_min_days: parts[3].parse().unwrap_or(0),
            change_max_days: parts[4].parse().unwrap_or(99999),
            change_warn_days: parts[5].parse().unwrap_or(7),
            change_inactive_days: parts[6].parse().unwrap_or(-1),
            expire_date: parts[7].parse().unwrap_or(-1),
            reserved: parts[8].parse().unwrap_or(0),
        })
    }
    Ok(entries)
}

pub fn read_group<R>(reader: BufReader<R>) -> Result<Vec<Group>>
where
    R: std::io::Read,
{
    let mut groups = Vec::new();
    for line in reader.lines() {
        let line = line?;
        let parts: Vec<_> = line.split(':').collect();
        groups.push(Group {
            name: parts[0].to_string(),
            passwd: parts[1].to_string(),
            gid: parts[2].parse()?,
            members: parts[3]
                .split(',')
                .collect::<Vec<_>>()
                .iter()
                .map(|s| s.to_string())
                .collect(),
        })
    }
    Ok(groups)
}

struct InfodPasswd;
libnss_passwd_hooks!(infod, InfodPasswd);

impl PasswdHooks for InfodPasswd {
    fn get_all_entries() -> Response<Vec<Passwd>> {
        let file = match File::open("/var/spool/infod/passwd") {
            Ok(file) => file,
            Err(_) => return Response::Unavail,
        };

        let users = match read_passwd(BufReader::new(file)) {
            Ok(users) => users,
            Err(_) => return Response::Unavail,
        };

        Response::Success(users)
    }

    fn get_entry_by_uid(uid: libc::uid_t) -> Response<Passwd> {
        match Self::get_all_entries() {
            Response::Success(users) => match users.into_iter().find(|u| u.uid == uid) {
                None => Response::NotFound,
                Some(u) => Response::Success(u),
            },
            _ => Response::Unavail,
        }
    }

    fn get_entry_by_name(name: String) -> Response<Passwd> {
        match Self::get_all_entries() {
            Response::Success(users) => match users.into_iter().find(|u| u.name == name) {
                None => Response::NotFound,
                Some(u) => Response::Success(u),
            },
            _ => Response::Unavail,
        }
    }
}

struct InfodGroup;
libnss_group_hooks!(infod, InfodGroup);

impl GroupHooks for InfodGroup {
    fn get_all_entries() -> Response<Vec<Group>> {
        let file = match File::open("/var/spool/infod/group") {
            Ok(file) => file,
            Err(_) => return Response::Unavail,
        };

        let groups = match read_group(BufReader::new(file)) {
            Ok(groups) => groups,
            Err(_) => return Response::Unavail,
        };

        Response::Success(groups)
    }

    fn get_entry_by_gid(gid: libc::gid_t) -> Response<Group> {
        match Self::get_all_entries() {
            Response::Success(groups) => match groups.into_iter().find(|g| g.gid == gid) {
                None => Response::NotFound,
                Some(g) => Response::Success(g),
            },
            _ => Response::Unavail,
        }
    }

    fn get_entry_by_name(name: String) -> Response<Group> {
        match Self::get_all_entries() {
            Response::Success(groups) => match groups.into_iter().find(|g| g.name == name) {
                None => Response::NotFound,
                Some(g) => Response::Success(g),
            },
            _ => Response::Unavail,
        }
    }
}

struct InfodShadow;
libnss_shadow_hooks!(infod, InfodShadow);

impl ShadowHooks for InfodShadow {
    fn get_all_entries() -> Response<Vec<Shadow>> {
        fn op() -> Result<Vec<Shadow>> {
            let file = File::open("/var/spool/infod/shadow")?;
            let shadow = read_shadow(BufReader::new(file))?;
            Ok(shadow)
        }

        match op() {
            Err(_) => Response::Unavail,
            Ok(r) => Response::Success(r),
        }
    }

    fn get_entry_by_name(name: String) -> Response<Shadow> {
        match Self::get_all_entries() {
            Response::Success(shadow) => match shadow.into_iter().find(|s| s.name == name) {
                None => Response::NotFound,
                Some(g) => Response::Success(g),
            },
            _ => Response::Unavail,
        }
    }
}

struct InfodHost;
libnss_host_hooks!(infod, InfodHost);

impl HostHooks for InfodHost {
    fn get_all_entries() -> Response<Vec<Host>> {
        Response::Success(vec![])
    }

    fn get_host_by_addr(_: IpAddr) -> Response<Host> {
        Response::NotFound
    }

    fn get_host_by_name(_: &str, _: AddressFamily) -> Response<Host> {
        Response::NotFound
    }
}

struct InfodInitgroups;
libnss_initgroups_hooks!(infod, InfodInitgroups);

impl InitgroupsHooks for InfodInitgroups {
    fn get_entries_by_user(user: String) -> Response<Vec<Group>> {
        match InfodGroup::get_all_entries() {
            Response::Success(groups) => Response::Success(
                groups
                    .into_iter()
                    .filter(|g| g.members.contains(&user))
                    .collect(),
            ),
            _ => Response::Unavail,
        }
    }
}
