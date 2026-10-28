from core.label_config import get_all_types, check_toname_in_config_by_regex, check_control_in_config_by_regex, \
    get_all_control_tag_tuples

config_string = """
<!--https://labelstud.io/templates/video_object_detector--><View>
   <Labels name="videoLabels" toName="video" allowEmpty="true">
     <Label value="box" background="#9254DE"/>
     <Label value="product" background="#df1616"/>
     <Label value="zuo_xia_hu_jiao" background="#54bcde"/>
     <Label value="you_xia_hu_jiao" background="#12eda4"/>
     <Label value="hu_jiao" background="#0b0b09"/>
     <Label value="shuo_ming_shu" background="#54dec7"/>
     <Label value="zuo_shang_hu_jiao" background="#afff09"/>
     <Label value="you_shang_hu_jiao" background="#fddec7"/>
     
     
     
     
   
    
  </Labels>
   
   <!-- Please specify FPS carefully, it will be used for all project videos -->
   <Video name="video" value="$video" framerate="$fps"/>
   <VideoRectangle name="box" toName="video"/>
  
</View><!--{
 "video": "/static/samples/opossum_snow.mp4"
}-->
"""
annotations_from_config = set(get_all_control_tag_tuples(config_string))
print(annotations_from_config)
from_name, to_name, t = 'label|video|labels'.split('|')
types = get_all_types(config_string)
print(1, types, from_name,to_name,t)
print(
    check_control_in_config_by_regex(config_string, from_name),
    check_toname_in_config_by_regex(config_string, to_name),
    t not in get_all_types(config_string)
)