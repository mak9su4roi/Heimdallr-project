from os import path, getcwd


def main():
    rc_path = path.expanduser("~") + "/.bashrc"
    project_root = getcwd()

    required = f"alias hmdl='sudo python3 {project_root}/heimdallr.py'"
    with open(rc_path, mode="r", encoding="UTF-8") as rc:
        bashrc = "".join(rc.readlines())

    if required not in bashrc:
        print("Not installed :=)")
        return 0

    with open(rc_path, mode="w", encoding="UTF-8") as rc:
        rc.write(bashrc.replace(required, "\n"))

    print("Successfully uninstalled :=)")


if __name__ == "__main__":
    main()
