#!/bin/bash
# Script om je fork bij te werken met de laatste wijzigingen uit upstream (colise/spiderweb)

set -e  # stop bij fouten

echo ">>> Stap 1: ophalen laatste wijzigingen uit upstream"
git fetch upstream

echo ">>> Stap 2: mergen met jouw branch main"
git merge upstream/main

echo ">>> Stap 3: pushen naar jouw fork (origin)"
git push origin main

echo ">>> Klaar! Je fork staat nu gelijk met upstream."
