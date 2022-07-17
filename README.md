Tuple Launch Process
================================================================================
Tuple requires privileged access that the flatpak portal doesn't provide.  To
accomodate this, Tuple prompts the user to install a privileged daemon.

The privileged daemon is split into 2 static executables:

1. `tuple-launch`
2. `tuple-flatpak-launch`

`tuple-launch` is what the user installs to their host filesystem.  It gains
root access via SUID. It's only job is to find, verify and launch
`tuple-flatpak-launch`.

`tuple-flatpak-launch` remains inside the Tuple flatpak so it will be updated
alongside Tuple.  Splitting the daemon up like this means the user won't need
to re-install the privileged daemon every time it changes.

Since `tuple-flatpak-launch` can change, it's important that `tuple-launch`
verifies it came from Tuple.  We do this with an ed25519 signature. This
verification is made easier because `tuple-flatpak-launch` is a static
executable.  This makes it trival load it into memory, verify it, then execute
it in-place.  This eliminates the disk as an attack vector.
