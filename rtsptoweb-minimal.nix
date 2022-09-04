{ lib, pkgs, options, config, ... }:
with lib;
let
  rtspToWebMinimal = pkgs.callPackage ./default.nix {};
  cfg = config.services.rtsptoweb-minimal;
  configPath = pkgs.writeText "rtsptoweb-minimal.json" (builtins.toJSON cfg.config);
in {
  options.services.rtsptoweb-minimal = {
    enable = mkEnableOption "rtsptoweb-minimal service";
    config = mkOption { }; /* todo: add schema */
  };

  config = mkIf cfg.enable {
    environment.systemPackages = [ rtspToWebMinimal ];

    systemd.services.rtsptoweb-minimal = {
      wantedBy = [ "multi-user.target" ];
      after = ["networking.target"];
      serviceConfig = {
        DynamicUser = true;
        ExecStart = "${rtspToWebMinimal}/bin/rtsptoweb-minimal -config '${configPath}'";
        LockPersonality = true;
        MemoryDenyWriteExecute = true;
        PrivateDevices = true;
        PrivateUsers = true;
        ProtectControlGroups = true;
        ProtectHome = true;
        ProtectKernelLogs = true;
        ProtectKernelModules = true;
        ProtectKernelTunables = true;
        RestrictNamespaces = true;
        RestrictRealtime = true;
        Restart = "on-failure";
        RestartSec = 60;
      };
    };

  };
}
