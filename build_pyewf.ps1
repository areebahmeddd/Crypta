# Ensure you have necessary tools
if (-not (Get-Command git -ErrorAction SilentlyContinue)) {
    Write-Error "Git is not installed. Please install Git and try again."
    exit 1
}

# Clone the repository if not already cloned
if (-not (Test-Path -Path "libewf")) {
    git clone https://github.com/libyal/libewf.git
}

# Change directory to libewf
Set-Location -Path "libewf"

# Run necessary build commands
.\synclibs.ps1
.\syncwinflexbison.ps1
.\synczlib.ps1
.\autogen.ps1

# Install pyewf
pip install .

# Return to the parent directory
Set-Location -Path ".."

# Remove the cloned repository
Remove-Item -Recurse -Force "libewf"

Write-Host "Installation complete and repository cleaned up."
