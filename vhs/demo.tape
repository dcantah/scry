# scry demo: render with: vhs demo.tape
#
# Prereqs: an nginx container named `scry-demo` is running, e.g.
#   docker run -d --name scry-demo -p 8080:80 nginx:stable

Output demo.gif

Set Shell bash
Set FontSize 14
Set Width 1280
Set Height 800
Set Theme "Catppuccin Mocha"
Set TypingSpeed 45ms
Set Padding 18

# Attach straight to the nginx master inside the container
Type 'sudo $(which scry) --pid $(docker inspect -f "{{.State.Pid}}" scry-demo)'
Enter
Sleep 2s

# Memory map
Enter
Sleep 3500ms
Escape
Sleep 800ms

# Child process tree
Down Down
Enter
Sleep 3500ms
Escape
Sleep 800ms

# Open file descriptors
Down
Enter
Sleep 3500ms
Escape
Sleep 800ms

# Namespaces
Down Down Down Down Down
Enter
Sleep 3500ms
Escape
Sleep 800ms

# Security overview
Down
Enter
Sleep 3500ms
Escape
Sleep 800ms

Type "q"
Sleep 1s
