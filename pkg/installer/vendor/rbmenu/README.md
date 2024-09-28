# RBMenu

Rust Bookmark (d)Menu is a dmenu/ncurses based interface to manage bookmarks independently of your web browser. It also supports file/folder bookmarks

Find a TUI version of RBMenu [here](https://github.com/DevHyperCoder/rbmenu-tui)

## Features
- Insert Bookmark
- List Bookmark(s) \[With coloured output]
- Remove Bookmark
- Edit Bookmarks
- Copy to clipboard (Available on [rbmenu-tui](https://github.com/DevHyperCoder/rbmenu-tui))

## FAQ
**Location of Bookmark file ?**
The Bookmark file for `rbmenu` is stored in `~/.local/share/rbmenu/`

**File format of the file ?**
The Bookmark file is stored in `json` format.

**More features ?**
Yes, more features are on the way. Some planned ones are, groups for bookmarks

## Installation
`rbmenu` is available on [crates.io](https://crates.io/crates/rbmenu)

**Arch Linux** : Available on AUR, `rbmenu` for manual compilation from release and `rbmenu-bin` for precompiled binary

**Manual Installation**
- Install the rust toolchain. `cargo` should be on the `$PATH`
- Clone the repo: `git clone https://github.com/DevHyperCoder/rbmenu.git`. Change directory (`cd`) into the `rbmenu` folder
- Build the code: `cargo build --release`
- Copy the binary to a location on $PATH. Binary is in `./target/release/rbmenu`
- For operation with cargo, `cargo run -- <options>`.

## CLI - Options

| Option / Flags     | Description                |
| ------------------ | -------------------------- |
| `-h` `--help`      | Prints help information    |
| `-V`               | Prints version information |
| `-n` `--name`      | Name of the bookmark       |
| `-i` `--id`        | Id of the bookmark         |
| `-u` `--url`       | Url of the bookmark        |
| `-l` `--show-link` | Show link of the bookmark  |

## CLI - Subcommands

| Subcommands      |                            |
| `list`           | List all bookmarks         |
| `insert`         | Add new bookmark           |
| `update`         | Update bookmarks           |
| `remove`         | List all bookmarks         |

## Examples
> Scripts working with `dmenu` or `rofi` would be published soon.
**Insert a new bookmark**

- `-n` is the name of the bookmark. (Not required as if not provided, the domain name is used)
- `-u` is the link of the bookmark.

`rbmenu insert -u "https://domain.com" -n "Name"`

**List bookmarks**

Without the name option, `rbmenu list` displays all the available bookmarks. Give a regex string to the `-n` flag to filter out the bookmarks

- `-n` is the name of the bookmark.
- `-i` is the id of the bookmark.

`rbmenu list -n "git*"` 

To just get the link of a bookmark, use the `-l` option.

`rbmenu list -n "git*" -l` will return just the links of the bookmarks.

**Remove Bookmark**

- `-n` is the name of the bookmark.
- `-i` is the id of the bookmark.

**Update Bookmark**

- `-n` is the name of the bookmark.
- `-u` is the link of the bookmark.
- `-i` is the id of the bookmark. REQUIRED

## License

RBMenu is licensed under the GPL-3 license.
