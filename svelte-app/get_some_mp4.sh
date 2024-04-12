# download the videos from a local server to avoid rate limits at point of origin.
for vid in vt-tour.mp4 CoffeeRun.mp4 Spring.mp4 Agent327.mp4 Hero.mp4
do
    wget -O build/${vid} https://courses.cs.vt.edu/cs3214/videos/demomp4s/${vid}
done

#
# all videos should have a suitable license
#
# wget -O build/CoffeeRun.mp4 https://res.cloudinary.com/dvm02rtnk/video/upload/w_1024,q_auto/v1628059304/blender/Coffee_Run_Blender_Open_Movie_1080p_bj9v97.mp4
# wget -O build/Spring.mp4  https://res.cloudinary.com/dvm02rtnk/video/upload/v1628057422/blender/Spring_Blender_Open_Movie_1080p_nmkckb.mp4
# wget -O build/Agent327.mp4 https://res.cloudinary.com/dvm02rtnk/video/upload/v1628057411/blender/Agent_327_Operation_Barbershop_1080p_hf1iq7.mp4
# wget -O build/Hero.mp4 https://res.cloudinary.com/dvm02rtnk/video/upload/v1628057414/blender/HERO_Blender_Grease_Pencil_Showcase_1080p_ctsjpy.mp4

