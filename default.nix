{ stdenv, lib }:

stdenv.mkDerivation rec {
  name = "rtsptoweb-minimal-${version}";
  version = "a6d0300";

  /* Use a static cross-compiled pre-built binary to deploy to embedded hosts. */
  src = [ ./rtsptoweb-minimal ];

  unpackPhase = ''
    for srcFile in $src; do
      cp $srcFile $(stripHash $srcFile)
    done
  '';

  installPhase = ''
    install -m755 -D rtsptoweb-minimal $out/bin/rtsptoweb-minimal
  '';

  meta = with lib; {
    description = "Publishes RTSP streams to WebRTC";
    platforms = platforms.linux;
  };
}
