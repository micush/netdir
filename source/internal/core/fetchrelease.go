package core

// The newest release fetched from GitHub, for Updates ▸ Upload a release when "Get the newest release from GitHub" is
// ticked.  It looks for the tag the way get.sh does: the newest published release, otherwise the highest v<number> tag,
// downloads that tag's source archive and hands it to the same staging as an uploaded file.  Variables only so tests can
// point them at a fake server.
const DefaultRepo = "micush/netdir"

var GhRepo = DefaultRepo

// Repo is the repository to fetch releases from: the one set in the update settings, or the default.
func (u *Updater) Repo() string {
	if r := u.Intent().Repo; r != "" {
		return r
	}
	return GhRepo
}
