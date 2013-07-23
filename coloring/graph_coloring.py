#!/usr/bin/python
# -*- coding: utf-8 -*-

import random
import collections
import multiprocessing

# seed fixe
random = random.Random(2509)

def greedy_colorize(graph):
    """
    algorithme glouton qui choisit le noeud ayant le plus de voisins sans couleur
    et la plus petite couleur licite disponible
    """
    nodeCount = len(graph)
    vertices  = set(xrange(nodeCount))
    color     = [-1 for i in xrange(nodeCount)]
    influence = [len(graph[i]) for i in xrange(nodeCount)]

    for _ in xrange(nodeCount):
	node = max(vertices, key=lambda v: influence[v])
	forbidden_colors = set(color[i] for i in graph[node])

	color[node] = next(c for c in xrange(nodeCount) if c not in forbidden_colors)
	vertices.remove(node)
	for v in graph[node]:
	    influence[v] -= 1

    return color

def constraint_colorize_init(graph, C):
    """
    initialisation pour l'algorithme force brute
    tente de supprimer le plus possible de symetries
    ordonne les noeuds de facon a echouer le plus vite possible
    ne controle pas si C est trop petit
    """
    nodeCount = len(graph)
    color  = [-1 for i in xrange(nodeCount)]

    # contraintes:
    # is_legal_color = couleurs encore licites pour le noeud
    # min_legal_color= plus petite couleur acceptable (detection de configurations impossibles)
    # influence      = nombre de noeuds que le noeud choisi contraint
    is_legal_color  = [[True for i in xrange(C)] for j in xrange(nodeCount)]
    min_legal_color = [0 for i in xrange(nodeCount)]
    influence       = [len(graph[i]) for i in xrange(nodeCount)]

    vertices = set(xrange(nodeCount))
    ordered_nodes = [-1 for i in xrange(nodeCount)]

    # suppression de solutions symetriques - reduction du nombre de configurations analysees
    # parametre pour fixer le nombre de noeuds contraints
    # choix du noeud ayant le plus de couleurs licites (suppression du maximum de branches)
    fixed = min(2, C)
    for n in xrange(fixed):
	node = max(vertices, key=lambda v: (sum(is_legal_color[v]), influence[v]))
	vertices.remove(node)
	ordered_nodes[n] = node

	forbidden_colors = set(color[i] for i in graph[node])
	c = color[node] = max((c for c in xrange(C) if c not in forbidden_colors), key=lambda x: sum(is_legal_color[v][x] for v in graph[node]))

	# propagation des nouvelles contraintes
	# suppression de la couleur pour les voisins
	# maj de la couleur minimale
	for col in xrange(C):
	    if col != c:
		is_legal_color[node][col] = False

	for v in graph[node]:
	    if color[v] > -1: continue
	    if is_legal_color[v][c]:
		influence[v] -= 1
		is_legal_color[v][c] = False
		while min_legal_color[v] < C and not is_legal_color[v][min_legal_color[v]]: min_legal_color[v] += 1

    # ordonnancement des noeuds restants selon le critere: le moins de couleurs licites possibles,
    # le plus grand nombre de voisins sans couleur
    for i in range(fixed, nodeCount):
	ordered_nodes[i] = max(vertices, key=lambda v: (-sum(is_legal_color[v]), influence[v]))
	vertices.remove(ordered_nodes[i])

    return ordered_nodes, color, min_legal_color, is_legal_color

def constraint_colorize(graph, C):
    """
    algorithme force brute avec propagation de contraintes
    recherche par backtracking et quelques detections de consistence de contraintes
    elagage de certaines solutions avec suppression de symetries
    choix de traitement des noeuds avec MRV (choix du moindre branchement)
    algorithme iteratif pour accepter toute profondeur de recursion
    """

    ordered_nodes, color, min_legal_color, is_legal_color = constraint_colorize_init(graph, C)
    nodeCount = len(graph)
    n = sum(1 if c != -1 else 0 for c in color)

    # memoire pre-allouee pour les changements (evite de solliciter la methode append)
    changes = [[None for j in xrange(len(graph[ordered_nodes[i]]))] for i in xrange(nodeCount)]
    changes_count = [0 for i in xrange(nodeCount)]

    while -1 < n < nodeCount:
	node = ordered_nodes[n]
	change = changes[n]
	if color[node] == -1:
	    color[node] = min_legal_color[node] - 1
	else:
	    # annule les changes[n]
	    for i in xrange(changes_count[n]):
		(vertex, c1, c2) = change[i]
	        is_legal_color[vertex][c1] = True
	        min_legal_color[vertex] = c2
	    changes_count[n] = 0

	# selection d'une couleur licite pour le noeud n
	c = color[node] + 1
	while c != C and not is_legal_color[node][c]: c += 1
	if c == C:
	    # echec: la configuration n'est pas viable: retour en arriere
	    color[node] = -1
	    n -= 1
	    continue 

	# propagation de la nouvelle contrainte
	constraints_satisfied = True
	for v in graph[node]:
	    if color[v] > -1: continue

	    if is_legal_color[v][c]:
		m = min_legal_color[v]
		is_legal_color[v][c] = False
		while min_legal_color[v] < C and not is_legal_color[v][min_legal_color[v]]: min_legal_color[v] += 1
		change[changes_count[n]] = (v,c,m)
		changes_count[n] += 1
		    
		if min_legal_color[v] > C:
		    constraints_satisfied = False
		    break

	# maj de la configuration
	color[node] = c
	if constraints_satisfied: n += 1

    return color if n == nodeCount else None

def dichotomic_search(graph):
    """
    recherche par dichotomie du nombre chromatique du graphe
    initialise une premiere solution avec l'algorithme glouton
    cherche des bornes inf et sup pour le nombre chromatique
    cherche la solution optimale en appliquant l'algorithme force brute
    """
    solution = greedy_colorize(graph)

    # bornes inf et sup
    k2 = max(solution) + 1
    k1 = int(.5 * k2)
    while k1 >= 0:
	sol2 = constraint_colorize(graph, k1)
	if sol2: 
	    k2 = k1
	    solution = sol2
	    k1 = max(min(int(0.75*k1), k1-1), 0)
	else: break

    # dichotomie
    while k1 < k2:
	k = int((k1 + k2) * .5)
	if   k == k1: sol2 = None
	elif k == k2: sol2 = solution
	else:         sol2 = constraint_colorize(graph, k)

	if sol2:
	    solution = sol2
	    k2 = max(solution) + 1
	else:
	    k1 = k if k != k1 else k+1

    return solution

# une fonction pour limiter le temps d'un appel a une fonction est requis ici
# l'erreur retournee quand l'appel est trop long
class TimeoutException(Exception): pass 

def set_timeout(fn, timeout):
    """
    decorateur pour fixer une limite de temps a l'execution d'une fonction
    utilise multiprocessing plutot que threading pour eviter le risque de lock du GIL
    """
    result = multiprocessing.Queue()

    def __fn(*args, **kwargs):
	result.put(fn(*args, **kwargs))

    def _fn(*args, **kwargs):
	t = multiprocessing.Process(target=__fn, name=fn.__name__, args=args, kwargs=kwargs)
	t.start()
	t.join(timeout)
	if t.is_alive():
	    t.terminate()
	    raise TimeoutException
	return result.get_nowait()

    return _fn


def local_search(graph, timeout=60):
    """
    algorithme probabiliste
    selectionne au hasard une contrainte, la resoud de la facon la moins perturbatrice possible
    itere tant qu'une configuration admissible n'est pas trouvee jusqu'au timeout
    l'optimalite n'est pas garantie
    """
    solution = greedy_colorize(graph)

    def local_improvement(solution_0):
	"""
	algorithme probabiliste qui tente de trouver un coloriage ayant moins de couleurs que solution_0
	"""
	nodeCount = len(solution_0)
	solution = list(solution_0)
	unsatisfied_constraints = set()
	C = max(solution)

	# suppression des noeuds de couleur C
	for node in xrange(nodeCount):
	    if solution[node] == C:
		solution[node] = -1

	# donne une couleur aux noeuds sans couleur, une de celles les moins contraignantes
	# pour cela, on compte le nombre d'occurences de chaque couleur parmi les voisins et on retient
	# une de celles vues le moins
	# maj des contraintes non respectees qui apparaissent
	for node in xrange(nodeCount):
	    if solution[node] == -1:
		distrib = collections.Counter(solution[v] for v in graph[node] if solution[v] > -1)
		least_represented = 0 
		if len(distrib) == C:
		    least_represented = min(distrib.values())
		candidates = [c for c in xrange(C) if distrib[c] == least_represented]
		col = solution[node] = random.choice(candidates)
		unsatisfied_constraints |= set((node,v) for v in graph[node] if solution[v] == col)

	# selectionne au hasard une contrainte, la resoud et met a jour les contraintes presentes
	while unsatisfied_constraints:
	    constraint = random.sample(unsatisfied_constraints, 1)[0]
	    (u,v) = constraint
	    # verifie si la contrainte n'a pas resolue avant
	    if solution[u] == solution[v]:
		distrib = collections.Counter(solution[w] for w in graph[v])
		del distrib[solution[u]]
		least_represented = 0 
		if len(distrib) == C-1:
		    least_represented = min(distrib.values())
		candidates = [c for c in xrange(C) if distrib[c] == least_represented and c != solution[u]]
	        col = solution[v] = random.choice(candidates)
	        unsatisfied_constraints |= set((v,w) for w in graph[v] if solution[w] == col)
	    unsatisfied_constraints.remove(constraint)

	return solution

    # la recherche proprement dite
    # tente d'iterer tant qu'on trouve une amelioration en temps raisonnable
    local_improvement = set_timeout(local_improvement, timeout)

    try:
        while True:
	   solution = local_improvement(solution)
    except TimeoutException:
        pass

    return solution

def solveIt(inputData):
    # Modify this code to run your optimization algorithm

    # parse the input
    lines = inputData.split('\n')

    firstLine = lines[0].split()
    nodeCount = int(firstLine[0])
    edgeCount = int(firstLine[1])

    edges = []
    for i in range(1, edgeCount + 1):
        line = lines[i]
        parts = line.split()
        edges.append((int(parts[0]), int(parts[1])))

    # build a trivial solution
    # every node has its own color
    solution = range(0, nodeCount)

    graph  = [[] for i in xrange(nodeCount)]
    for (u,v) in edges:
	graph[u].append(v)
	graph[v].append(u)

    def is_valid(solution):
	for (u,v) in edges:
	    if solution[u] == solution[v]: return False
	return all(color >= 0 for color in solution)

    # selection of the solver
    #solver = dichotomic_search
    solver = local_search

    solution = solver(graph) 
    assert is_valid(solution)

    # prepare the solution in the specified output format
    #outputData = str(nodeCount) + ' ' + str(0) + '\n'
    outputData = str(1 + max(solution)) + ' ' + str(0) + '\n'
    outputData += ' '.join(map(str, solution))

    return outputData


import sys

if __name__ == '__main__':
    if len(sys.argv) > 1:
        fileLocation = sys.argv[1].strip()
        inputDataFile = open(fileLocation, 'r')
        inputData = ''.join(inputDataFile.readlines())
        inputDataFile.close()
        print solveIt(inputData)
    else:
        print 'This test requires an input file.  Please select one from the data directory. (i.e. python solver.py ./data/gc_4_1)'

