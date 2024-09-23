#!/bin/bash

kubectl get nodes

kubectl delete secret harbor-ingress-tls -n harbor

helm delete harbor -n harbor
for pvc in $(kubectl get pvc -n harbor -o name);  do kubectl delete -n harbor $pvc; done

helm delete gitlab -n gitlab
for pvc in $(kubectl get pvc -n gitlab -o name);  do kubectl delete -n gitlab $pvc; done
