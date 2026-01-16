{ lib
, rustPlatform
, fetchFromGitHub
, pkg-config
, dbus
, openssl
, librsvg
, webkitgtk_4_1
, gtk3
, libsoup_3
, cairo
, gdk-pixbuf
, glib
, pango
, atkmm
, at-spi2-atk
, harfbuzz
, pcsclite
, hidapi
, udev
, libglvnd
, libGL
, vulkan-loader
, mesa
, gst_all_1
, deno
, nodejs
, cargo
, rustc
, stdenv
, copyDesktopItems
, cacert
}:

let
  pname = "picoforge";
  version = "0.2.0";

  src = fetchFromGitHub {
    owner = "librekeys";
    repo = "picoforge";
    rev = "v${version}"; # Assuming tags are like v0.2.0
    hash = "sha256-xc25LnDoIRwCT9QrTEAOiy0H7iVAL8DNCbLo2yhRwfQ=";
  };

  # Fixed-output derivation to cache Deno dependencies
  denoDeps = stdenv.mkDerivation {
    name = "${pname}-deno-deps";
    inherit src;
    nativeBuildInputs = [ deno cacert ];
    SSL_CERT_FILE = "${cacert}/etc/ssl/certs/ca-bundle.crt";
    buildPhase = ''
      export DENO_DIR=$out
      # This will download all dependencies into $out
      deno install --frozen
    '';
    # This hash must be updated whenever deno.lock or dependencies change.
    # Initially set to a dummy value so Nix shows the actual hash.
    outputHashAlgo = "sha256";
    outputHashMode = "recursive";
    outputHash = "sha256-/fPDCciOQsDLPfibk5S8xkYerBgicxohD2i3jRZbBxA=";
  };

in
rustPlatform.buildRustPackage {
  inherit pname version src;

  cargoRoot = "src-tauri";
  cargoLock = {
    lockFile = ./src-tauri/Cargo.lock;
  };

  nativeBuildInputs = [
    pkg-config
    deno
    nodejs
    cargo
    rustc
    copyDesktopItems
  ];

  buildInputs = [
    dbus
    openssl
    librsvg
    webkitgtk_4_1
    gtk3
    libsoup_3
    cairo
    gdk-pixbuf
    glib
    pango
    atkmm
    at-spi2-atk
    harfbuzz
    pcsclite
    hidapi
    udev
    libglvnd
    libGL
    vulkan-loader
    mesa
    gst_all_1.gst-plugins-base
    gst_all_1.gst-plugins-good
  ];

  # Pre-build step for the frontend
  preBuild = ''
    # Ensure a clean and writable environment
    rm -rf node_modules
    chmod -R +w .
    
    # Use the pre-cached Deno dependencies
    export DENO_DIR=${denoDeps}
    export HOME=$(mktemp -d)
    
    # Populate node_modules from the cache (hermetically)
    deno install --frozen
    
    # Deno task build runs vite build
    deno task build
  '';

  postInstall = ''
    # Install icons and desktop files
    install -Dm644 src-tauri/icons/128x128.png $out/share/icons/hicolor/128x128/apps/picoforge.png
  '';

  meta = with lib; {
    description = "An open source commissioning tool for Pico FIDO security keys";
    homepage = "https://github.com/librekeys/picoforge";
    license = licenses.agpl3Only;
    maintainers = [ ];
    platforms = platforms.linux;
  };
}
