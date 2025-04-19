import os
import sys

# Add parent directories to path for imports
current_dir = os.path.dirname(os.path.abspath(__file__))
parent_dir = os.path.dirname(os.path.dirname(current_dir))
jacspy_dir = os.path.dirname(os.path.dirname(parent_dir))
sys.path.append(jacspy_dir)

# Import based on platform
if sys.platform == "darwin":
    try:
        import jacspy  # For macOS, assuming jacspy.so is in the parent directory
        print("jacspy imported successfully")
    except ImportError:
        print("Failed to import jacspy. Make sure jacspy.so is available.")
        sys.exit(1)
elif sys.platform == "linux":
    try:
        # For Linux, assuming jacspy is in a 'linux' subdirectory
        linux_dir = os.path.join(jacspy_dir, "linux")
        sys.path.append(linux_dir)
        from linux import jacspylinux as jacspy
    except ImportError:
        print("Failed to import jacspylinux. Make sure it's available in the linux directory.")
        sys.exit(1)
else:
    print(f"Unsupported platform: {sys.platform}")
    sys.exit(1)