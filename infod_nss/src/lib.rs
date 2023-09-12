#[macro_use]
extern crate lazy_static;

use std::fs::File;
use std::io::BufReader;
use std::net::IpAddr;

use color_eyre::eyre::Result;
use infod_common::{read_groups, read_shadow, read_users};
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

struct InfodPasswd;
libnss_passwd_hooks!(infod, InfodPasswd);

impl PasswdHooks for InfodPasswd {
    fn get_all_entries() -> Response<Vec<Passwd>> {
        let file = match File::open("/var/spool/infod/passwd") {
            Ok(file) => file,
            Err(_) => return Response::Unavail,
        };

        let users = match read_users(BufReader::new(file)) {
            Ok(users) => users,
            Err(_) => return Response::Unavail,
        };

        Response::Success(
            users
                .into_iter()
                .map(|u| Passwd {
                    name: u.username,
                    passwd: "x".to_string(),
                    uid: u.uid,
                    gid: u.gid,
                    gecos: u.gecos,
                    dir: u.home,
                    shell: u.shell,
                })
                .collect(),
        )
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

        let groups = match read_groups(BufReader::new(file)) {
            Ok(groups) => groups,
            Err(_) => return Response::Unavail,
        };

        Response::Success(
            groups
                .into_iter()
                .map(|g| Group {
                    name: g.name,
                    passwd: g.password,
                    gid: g.gid,
                    members: g.members,
                })
                .collect(),
        )
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
            Ok(shadow
                .into_iter()
                .filter_map(|e| -> Option<Shadow> {
                    Some(Shadow {
                        name: e.username,
                        passwd: e.pwdp,
                        last_change: e.lstchg.parse().unwrap_or(0),
                        change_min_days: e.min.parse().unwrap_or(0),
                        change_max_days: e.max.parse().unwrap_or(99999),
                        change_warn_days: e.warn.parse().unwrap_or(7),
                        change_inactive_days: e.inact.parse().unwrap_or(-1),
                        expire_date: e.expire.parse().unwrap_or(-1),
                        reserved: 0,
                    })
                })
                .collect())
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
