{
  lib,
  buildGoModule,
}:

buildGoModule {
  pname = "pacrat-server";
  version = "0.1.0";

  src = ./.;

  vendorHash = null;

  modRoot = "./server";

  preInstall =
    ''
      mv $GOPATH/bin/{server,pacrat-server}
    '';

  meta = with lib; {
    description = "A simple Arch Linux custom repository manager";
    homepage = "https://github.com/facekapow/pacrat";
    license = licenses.agpl3Plus;
    maintainers = [];
  };
}
