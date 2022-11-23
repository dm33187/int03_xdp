echo " "
echo "Creating Tuning Module Assessment package..."
cp ../assess-tuning/dtn_tune .
cp ../assess-tuning/dtnmenu .
cp ../assess-tuning/dtn_menu.sh .
cp ../assess-tuning/gdv.sh .
cp ../assess-tuning/gdv_100.sh .
cp ../assess-tuning/user_config.txt .
cp ../assess-tuning/common_irq_affinity.sh .
cp ../assess-tuning/set_irq_affinity.sh .
cp ../assess-tuning/readme.txt .

rm -f ASSESSdtntune.zip
zip ASSESSdtntune.zip dtn_tune gdv_100.sh gdv.sh readme.txt user_config.txt dtn_menu.sh dtnmenu common_irq_affinity.sh set_irq_affinity.sh
#

rm dtn_tune 
rm dtnmenu 
rm dtn_menu.sh 
rm gdv.sh 
rm gdv_100.sh 
rm user_config.txt 
rm common_irq_affinity.sh 
rm set_irq_affinity.sh 
rm readme.txt 
echo "Finished Creating Tuning Module Assessment package..."


echo " "
echo "Creating Tuning Module StandAlone package..."
cp ../cli/tmp/tuncli .
cp ../userspace/user_dtn .
cp ../userspace/userdtn_adm .
cp ../userspace/common_irq_affinity.sh .
cp ../userspace/set_irq_affinity.sh .
cp ../userspace/help_dtn.sh .
cp ../userspace/user_config.txt .
cp ../userspace/user_menu.sh .
cp ../userspace/gdv_100.sh .
cp ../userspace/gdv.sh .
cp ../userspace/readme.txt .
cp ../util/plotgraph.py .
cp ../util/conv_csv_to_json.py .
cp obj/int-sink2+filter.bpf.o .

rm -f SAdtntune.zip
zip SAdtntune.zip tuncli user_dtn userdtn_adm help_dtn.sh user_config.txt user_menu.sh gdv_100.sh gdv.sh readme.txt common_irq_affinity.sh set_irq_affinity.sh plotgraph.py conv_csv_to_json.py install.sh tuning_module.service int-sink2+filter.bpf.o
#
rm tuncli 
rm user_dtn 
rm userdtn_adm
rm common_irq_affinity.sh 
rm set_irq_affinity.sh 
rm help_dtn.sh 
rm user_config.txt 
rm user_menu.sh 
rm gdv_100.sh 
rm gdv.sh 
rm readme.txt 
rm plotgraph.py 
rm conv_csv_to_json.py 
rm int-sink2+filter.bpf.o
echo "Finished Creating Tuning Module StandAlone package..."

