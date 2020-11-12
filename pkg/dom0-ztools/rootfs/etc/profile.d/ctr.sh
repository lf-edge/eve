# make ctr commands default to using our user app namespace
# instead of default (where we don't run anything anyways)
CONTAINERD_NAMESPACE=eve-user-apps
export CONTAINERD_NAMESPACE
