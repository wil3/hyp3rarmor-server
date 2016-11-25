# Utility to copy the generated files to the visible server

SRC=
DST=
# Location where the generated files are put
WATCH_DIRECTORY=../gen/

# Watcht the directory, when a file changes, 
# upload to the destination
while inotifywait -r $WATCH_DIRECTORY; do
	rsync -aze ssh $SRC $DST
done
