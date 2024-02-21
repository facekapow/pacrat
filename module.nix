{ config, lib, pkgs, ... }:

with lib;
let
  cfg = config.services.pacrat;
  settingsFormat = pkgs.formats.toml {};
  settingsFile = settingsFormat.generate "pacrat.toml" cfg.settings;
in
{
  options = {
    services.pacrat = {
      enable = mkEnableOption (mdDoc "A simple Arch Linux custom repository manager");

      settings = mkOption {
        type = types.submodule {
          freeformType = settingsFormat.type;
          options = {};
        };
      };
    };
  };

  config = mkIf cfg.enable {
    systemd.services.pacrat = {
      description = "A simple Arch Linux custom repository manager";
      wantedBy = [ "multi-user.target" ];
      after = [ "network.target" ];
      serviceConfig = {
        Type = "simple";
        ExecStart = "${pkgs.pacrat-server}/bin/pacrat-server -c ${settingsFile}";
        WorkingDirectory = "/var/lib/pacrat";
        NoNewPrivileges = true;
        LockPersonality = true;
        MemoryDenyWriteExecute = true;
        PrivateMounts = "yes";
        PrivateTmp = "yes";
        ProtectSystem = "strict";
        ProtectHome = "yes";
        ProtectControlGroups = true;
        ProtectHostname = true;
        ProtectKernelModules = true;
        ProtectKernelTunables = true;
        ReadWritePaths = [
          "/var/lib/pacrat"
        ];
        RemoveIPC = true;
        RestrictAddressFamilies = [ "AF_INET" "AF_INET6" ];
        RestrictNamespaces = true;
        RestrictRealtime = true;
        RestrictSUIDSGID = true;
        SystemCallFilter = "@system-service";
        SystemCallArchitectures = "native";
      };
    };

    users.users.pacrat = {
      group = "pacrat";
      isSystemUser = true;
    };
    users.groups.pacrat = {};
  };
}
